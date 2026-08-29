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
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Domain registration facts via <b>RDAP</b> (Registration Data Access Protocol —
 * the IETF's structured, JSON replacement for WHOIS). We hit the public
 * bootstrap at {@code https://rdap.org/domain/<domain>}, which 302-redirects to
 * the authoritative registry's RDAP server.
 *
 * <p>This is exactly where "domain age" and "registrar" come from — the registry
 * records the {@code registration} event when a domain is first bought. Some
 * ccTLDs (and privacy-protected domains) return no data; the lookup then yields
 * {@link Optional#empty()} and the engine simply doesn't use an age signal.
 *
 * <p>Per the spec: domain age is a <i>risk indicator combined with other
 * evidence</i>, never proof of fraud on its own.
 */
@Service
public class DomainIntelService {

    private static final Logger log = LoggerFactory.getLogger(DomainIntelService.class);
    private static final Duration CACHE_TTL = Duration.ofHours(12);

    private final ObjectMapper mapper;
    private final HttpClient http;
    private final boolean enabled;
    private final ConcurrentHashMap<String, Cached> cache = new ConcurrentHashMap<>();

    private record Cached(DomainInfo info, Instant at) {}

    /**
     * @param registered  first registration instant (may be null)
     * @param ageDays      whole days since registration (null if unknown)
     * @param registrar    sponsoring registrar name (may be null)
     * @param expires      expiry instant (may be null)
     * @param source       always "RDAP" when data is present
     */
    public record DomainInfo(Instant registered, Integer ageDays, String registrar,
                             Instant expires, String source) {
        public boolean hasAge() { return ageDays != null; }
    }

    public DomainIntelService(ObjectMapper mapper,
                              @Value("${cybershield.rdap.enabled:true}") boolean enabled) {
        this.mapper = mapper;
        this.enabled = enabled;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .followRedirects(HttpClient.Redirect.NORMAL)   // rdap.org bootstrap redirects
                .build();
    }

    /** RDAP facts for the registrable domain of {@code host}, or empty (fail-open). */
    public Optional<DomainInfo> lookup(String host) {
        if (!enabled || host == null || host.isBlank()) return Optional.empty();
        String domain = registrableDomain(host.toLowerCase(Locale.ROOT).trim());
        if (domain == null) return Optional.empty();

        Cached c = cache.get(domain);
        if (c != null && Duration.between(c.at, Instant.now()).compareTo(CACHE_TTL) < 0) {
            return Optional.ofNullable(c.info);
        }

        DomainInfo info = null;
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create("https://rdap.org/domain/" + domain))
                    .timeout(Duration.ofSeconds(4))
                    .header("Accept", "application/rdap+json")
                    .GET()
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 200) {
                info = parse(resp.body());
            } else {
                log.debug("RDAP {} -> HTTP {}", domain, resp.statusCode());
            }
        } catch (Exception e) {
            log.debug("RDAP lookup failed for {} (fail-open): {}", domain, e.toString());
        }
        cache.put(domain, new Cached(info, Instant.now()));
        return Optional.ofNullable(info);
    }

    private DomainInfo parse(String body) {
        try {
            JsonNode root = mapper.readTree(body);
            Instant registered = null, expires = null;
            for (JsonNode ev : root.path("events")) {
                String action = ev.path("eventAction").asText("");
                String date = ev.path("eventDate").asText(null);
                if (date == null) continue;
                Instant when = OffsetDateTime.parse(date).toInstant();
                if (action.equals("registration")) registered = when;
                else if (action.equals("expiration")) expires = when;
            }
            String registrar = null;
            for (JsonNode ent : root.path("entities")) {
                for (JsonNode role : ent.path("roles")) {
                    if ("registrar".equals(role.asText())) {
                        registrar = vcardFullName(ent);
                    }
                }
            }
            Integer ageDays = registered == null ? null
                    : (int) ChronoUnit.DAYS.between(registered, Instant.now());
            if (registered == null && registrar == null) return null;
            return new DomainInfo(registered, ageDays, registrar, expires, "RDAP");
        } catch (Exception e) {
            log.debug("RDAP parse failed (fail-open): {}", e.toString());
            return null;
        }
    }

    private String vcardFullName(JsonNode entity) {
        // vcardArray = ["vcard", [ ["version",...], ["fn",{},"text","Registrar Name"], ... ]]
        JsonNode arr = entity.path("vcardArray");
        if (arr.isArray() && arr.size() == 2) {
            for (JsonNode item : arr.get(1)) {
                if (item.isArray() && item.size() >= 4 && "fn".equals(item.get(0).asText())) {
                    return item.get(3).asText(null);
                }
            }
        }
        return entity.path("handle").asText(null);
    }

    /** last two labels — good enough without a Public Suffix List. */
    public static String registrableDomain(String host) {
        if (host == null) return null;
        String h = host.endsWith(".") ? host.substring(0, host.length() - 1) : host;
        if (h.matches("^\\d{1,3}(\\.\\d{1,3}){3}$")) return null;   // IP, no RDAP domain
        String[] p = h.split("\\.");
        if (p.length < 2) return null;
        // crude 2-level ccTLD handling (co.in, co.uk, com.au, gov.in, ...)
        if (p.length >= 3) {
            String last2 = p[p.length - 2] + "." + p[p.length - 1];
            if (last2.matches("(co|com|net|org|gov|edu|ac|gob)\\.[a-z]{2}")) {
                return p[p.length - 3] + "." + last2;
            }
        }
        return p[p.length - 2] + "." + p[p.length - 1];
    }
}
