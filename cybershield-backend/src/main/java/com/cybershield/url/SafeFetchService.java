package com.cybershield.url;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * SSRF-hardened HTTP fetcher. The ONLY component allowed to make outbound
 * requests to user-supplied URLs (web-page analysis, redirect resolution).
 *
 * Defences:
 *  - scheme allowlist (http/https)
 *  - resolve DNS ourselves and check EVERY resolved IP with {@link IpGuard}
 *  - pin the validated IP; connect with an explicit Host header (DNS-rebinding safe)
 *  - redirects disabled; each hop re-validated manually up to a small cap
 *  - hard timeouts and a response-size ceiling
 *  - alternate IP representations normalised before checks
 */
@Service
public class SafeFetchService {

    private static final Logger log = LoggerFactory.getLogger(SafeFetchService.class);
    private static final int MAX_REDIRECTS = 4;
    private static final long MAX_BYTES = 2L * 1024 * 1024;

    private final IpGuard ipGuard;
    private final boolean fetchEnabled;
    private final HttpClient client;

    public SafeFetchService(IpGuard ipGuard,
                            @Value("${cybershield.fetch.enabled:true}") boolean fetchEnabled) {
        this.ipGuard = ipGuard;
        this.fetchEnabled = fetchEnabled;
        this.client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    public record FetchResult(String finalUrl, int status, String body,
                              List<String> redirectChain, boolean truncated) {}

    /**
     * Fetch a URL safely. Empty if fetching is disabled, the URL is unsafe,
     * or the request failed. Never throws for hostile input.
     */
    public Optional<FetchResult> fetch(String rawUrl) {
        if (!fetchEnabled) return Optional.empty();
        Optional<UrlParts> parsed = UrlParts.parse(rawUrl);
        if (parsed.isEmpty()) return Optional.empty();

        String current = parsed.get().original();
        var chain = new java.util.ArrayList<String>();
        try {
            for (int hop = 0; hop <= MAX_REDIRECTS; hop++) {
                Optional<UrlParts> up = UrlParts.parse(current);
                if (up.isEmpty()) return Optional.empty();
                UrlParts u = up.get();
                chain.add(u.original());

                InetAddress pinned = resolveAndValidate(u.host());
                if (pinned == null) {
                    log.warn("SSRF guard blocked host {}", safe(u.host()));
                    return Optional.empty();
                }

                HttpResponse<InputStream> resp = send(u, pinned);
                int sc = resp.statusCode();
                if (sc >= 300 && sc < 400) {
                    Optional<String> loc = resp.headers().firstValue("location");
                    if (loc.isEmpty()) return Optional.empty();
                    current = absolutize(u, loc.get());
                    continue;
                }
                var read = readCapped(resp.body());
                return Optional.of(new FetchResult(u.original(), sc, read.text(), chain, read.truncated()));
            }
            return Optional.empty(); // too many redirects
        } catch (IOException | InterruptedException | RuntimeException e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            log.debug("safe fetch failed for {}: {}", safe(rawUrl), e.toString());
            return Optional.empty();
        }
    }

    /** Resolve host, reject alternate encodings and any blocked IP. Returns the pinned address. */
    InetAddress resolveAndValidate(String host) {
        String h = ipGuard.normalizeNumericHost(host).toLowerCase(Locale.ROOT);
        if (ipGuard.isMetadataHostname(h)) return null;
        try {
            InetAddress[] all = InetAddress.getAllByName(h);
            InetAddress chosen = null;
            for (InetAddress a : all) {
                if (ipGuard.isBlocked(a)) return null; // any bad answer -> refuse
                if (chosen == null) chosen = a;
            }
            return chosen;
        } catch (Exception e) {
            return null;
        }
    }

    private HttpResponse<InputStream> send(UrlParts u, InetAddress pinned) throws IOException, InterruptedException {
        // Connect to the pinned IP, preserve Host header -> defeats DNS rebinding.
        int port = u.port() != -1 ? u.port() : (u.isHttps() ? 443 : 80);
        String connectUrl = u.scheme() + "://" + pinned.getHostAddress()
                + (isDefault(port, u.isHttps()) ? "" : ":" + port)
                + (u.path().isEmpty() ? "/" : u.path())
                + (u.query().isEmpty() ? "" : "?" + u.query());
        HttpRequest req = HttpRequest.newBuilder(URI.create(connectUrl))
                .timeout(Duration.ofSeconds(6))
                .header("Host", u.host())
                .header("User-Agent", "CyberShield-Analyzer/0.1 (+security-scan)")
                .header("Accept", "text/html,application/xhtml+xml")
                .GET()
                .build();
        return client.send(req, HttpResponse.BodyHandlers.ofInputStream());
    }

    private record Read(String text, boolean truncated) {}

    private Read readCapped(InputStream in) throws IOException {
        try (in) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            long total = 0;
            int n;
            boolean truncated = false;
            while ((n = in.read(buf)) != -1) {
                total += n;
                if (total > MAX_BYTES) {
                    out.write(buf, 0, (int) Math.max(0, n - (total - MAX_BYTES)));
                    truncated = true;
                    break;
                }
                out.write(buf, 0, n);
            }
            return new Read(out.toString(java.nio.charset.StandardCharsets.UTF_8), truncated);
        }
    }

    private static boolean isDefault(int port, boolean https) {
        return (https && port == 443) || (!https && port == 80);
    }

    private static String absolutize(UrlParts base, String location) {
        try {
            return base.original() != null
                    ? new URI(base.scheme() + "://" + base.host()
                        + (base.port() == -1 ? "" : ":" + base.port()) + "/")
                        .resolve(location).toString()
                    : location;
        } catch (Exception e) {
            return location;
        }
    }

    private static String safe(String s) {
        if (s == null) return "null";
        return s.replaceAll("[\\r\\n]", "_");
    }
}
