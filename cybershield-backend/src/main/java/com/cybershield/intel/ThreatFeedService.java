package com.cybershield.intel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Live reputation lookups against external feeds. Entirely optional and
 * fail-open: any misconfiguration, timeout or error yields "not known bad"
 * so analysis never blocks on a third party. Results are cached briefly.
 *
 *  - Google Safe Browsing  : needs GOOGLE_SAFE_BROWSING_KEY
 *  - URLhaus (abuse.ch)    : needs URLHAUS_AUTH_KEY (free)
 *
 * With neither configured the platform still works on its local seed lists
 * and community reports.
 */
@Service
public class ThreatFeedService {

    private static final Logger log = LoggerFactory.getLogger(ThreatFeedService.class);
    private static final Duration CACHE_TTL = Duration.ofMinutes(30);

    private final ObjectMapper mapper;
    private final HttpClient http;
    private final String safeBrowsingKey;
    private final String urlhausKey;
    private final boolean enabled;

    private final Map<String, Cached> cache = new ConcurrentHashMap<>();

    private record Cached(boolean malicious, String source, Instant at) {}

    public ThreatFeedService(ObjectMapper mapper,
                             @Value("${GOOGLE_SAFE_BROWSING_KEY:}") String safeBrowsingKey,
                             @Value("${URLHAUS_AUTH_KEY:}") String urlhausKey,
                             @Value("${cybershield.feeds.enabled:true}") boolean enabled) {
        this.mapper = mapper;
        this.safeBrowsingKey = safeBrowsingKey == null ? "" : safeBrowsingKey.trim();
        this.urlhausKey = urlhausKey == null ? "" : urlhausKey.trim();
        this.enabled = enabled;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(4))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    public boolean anyConfigured() {
        return enabled && (!safeBrowsingKey.isEmpty() || !urlhausKey.isEmpty());
    }

    public record Hit(boolean malicious, String source) {
        static Hit clean() { return new Hit(false, null); }
    }

    /** True if any configured feed flags this URL/host as malicious. */
    public Hit check(String url, String host) {
        if (!anyConfigured() || url == null || url.isBlank()) return Hit.clean();

        Cached c = cache.get(url);
        if (c != null && Duration.between(c.at, Instant.now()).compareTo(CACHE_TTL) < 0) {
            return new Hit(c.malicious, c.source);
        }

        Hit result = Hit.clean();
        try {
            if (!safeBrowsingKey.isEmpty() && safeBrowsingHit(url)) {
                result = new Hit(true, "Google Safe Browsing");
            } else if (!urlhausKey.isEmpty() && urlhausHit(host)) {
                result = new Hit(true, "URLhaus");
            }
        } catch (Exception e) {
            log.debug("threat feed check failed (fail-open): {}", e.toString());
        }
        cache.put(url, new Cached(result.malicious(), result.source(), Instant.now()));
        return result;
    }

    private boolean safeBrowsingHit(String url) throws Exception {
        String body = """
            {"client":{"clientId":"cybershield","clientVersion":"0.1"},
             "threatInfo":{
               "threatTypes":["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
               "platformTypes":["ANY_PLATFORM"],
               "threatEntryTypes":["URL"],
               "threatEntries":[{"url":%s}]}}
            """.formatted(mapper.writeValueAsString(url));
        HttpRequest req = HttpRequest.newBuilder(URI.create(
                        "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + safeBrowsingKey))
                .timeout(Duration.ofSeconds(5))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) return false;
        JsonNode n = mapper.readTree(resp.body());
        return n.has("matches") && n.get("matches").size() > 0;
    }

    private boolean urlhausHit(String host) throws Exception {
        if (host == null || host.isBlank()) return false;
        HttpRequest req = HttpRequest.newBuilder(URI.create("https://urlhaus-api.abuse.ch/v1/host/"))
                .timeout(Duration.ofSeconds(5))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Auth-Key", urlhausKey)
                .POST(HttpRequest.BodyPublishers.ofString("host=" + host))
                .build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) return false;
        JsonNode n = mapper.readTree(resp.body());
        if (!"ok".equals(n.path("query_status").asText())) return false;
        JsonNode urls = n.path("urls");
        for (JsonNode u : urls) {
            if ("online".equalsIgnoreCase(u.path("url_status").asText())) return true;
        }
        return urls.size() > 0;
    }
}
