package com.cybershield.forensics;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * GeoLocation & ASN/ISP Intelligence Service.
 *
 * Distinguishes:
 * 1. Reporter/device GPS location (collected on mobile with user consent, separate from email).
 * 2. Approximate email relay IP location (intermediate transit infrastructure).
 * 3. Sender physical location (cannot be definitively established from email headers alone).
 *
 * For bundled offline demonstration samples, curated fixture entries are explicitly
 * labeled as DEMO_FIXTURE so they are never confused with live intelligence.
 * All public IPs are queried live against ip-api.com. If unavailable, unresolvable,
 * or rate-limited, explicit UNAVAILABLE statuses with null coordinates are returned.
 * Fabricated coordinates (e.g. 20.5937, 78.9629 or pseudo-random city buckets) are strictly prohibited.
 */
@Service
public class GeoLocationService {

    private static final Logger log = LoggerFactory.getLogger(GeoLocationService.class);

    public record GeoData(
            String ip,
            String city,
            String region,
            String country,
            String countryCode,
            Double latitude,
            Double longitude,
            String asn,
            String isp,
            boolean isDatacenter,
            boolean isTorOrProxy,
            boolean isPrivate,
            int riskScore,
            String riskReason,
            String lookupStatus,       // RESOLVED, PRIVATE_NETWORK, DEMO_FIXTURE, UNAVAILABLE, RATE_LIMITED
            String dataSource,         // Live provider name, RFC range, or Bundled Demo Fixture
            Double accuracyRadiusKm,   // Provider-supported accuracy radius if available, else null
            String lookupTimestamp     // ISO-8601 timestamp of lookup
    ) {
        // 14-parameter constructor for backwards compatibility with any existing callers
        public GeoData(String ip, String city, String region, String country, String countryCode,
                       Double latitude, Double longitude, String asn, String isp,
                       boolean isDatacenter, boolean isTorOrProxy, boolean isPrivate,
                       int riskScore, String riskReason) {
            this(ip, city, region, country, countryCode, latitude, longitude, asn, isp,
                 isDatacenter, isTorOrProxy, isPrivate, riskScore, riskReason,
                 isPrivate ? "PRIVATE_NETWORK" : (latitude != null ? "RESOLVED" : "UNAVAILABLE"),
                 isPrivate ? "Private Address Space" : "Live Lookup / Cached",
                 null, Instant.now().toString());
        }

        public static GeoData privateSubnet(String ip) {
            return new GeoData(
                    ip, "Internal Network", "Local Subnet", "Private / Reserved Range", "LAN",
                    null, null, "AS0 (Private)", "Local Intranet / NAT / Reserved",
                    false, false, true, 0, "Internal organization / private relay hop",
                    "PRIVATE_NETWORK", "RFC 1918 / IANA Reserved Address Space",
                    null, Instant.now().toString()
            );
        }

        public static GeoData unknown(String ip, String reason, String status) {
            return new GeoData(
                    ip, "Unavailable", "Unavailable", "Unavailable", "XX",
                    null, null, "AS-UNKNOWN", "Unknown Network Operator",
                    false, false, false, 0, reason,
                    status != null ? status : "UNAVAILABLE", "Unresolvable public IP",
                    null, Instant.now().toString()
            );
        }

        public static GeoData unknown(String ip) {
            return unknown(ip, "Unresolvable public IP address", "UNAVAILABLE");
        }
    }

    /**
     * Isolated demo fixtures matching only the exact IP addresses used in bundled sample emails.
     * Clearly flagged with lookupStatus = "DEMO_FIXTURE" so that demonstration mock data
     * is transparent and never conflated with live intelligence.
     */
    private static final Map<String, GeoData> DEMO_FIXTURES = Map.of(
            "91.240.118.42", new GeoData(
                    "91.240.118.42", "Saint Petersburg", "Saint Petersburg", "Russia", "RU",
                    59.9311, 30.3609, "AS44050", "Petersburg Internet Network / Bulletproof Host",
                    true, false, false, 80, "[Demo Sample Fixture] Unregulated hosting infrastructure tied to sample phishing kit",
                    "DEMO_FIXTURE", "Bundled Demo Sample (Offline Presentation Fixture)", 25.0, Instant.now().toString()
            ),
            "185.220.101.5", new GeoData(
                    "185.220.101.5", "Frankfurt am Main", "Hesse", "Germany", "DE",
                    50.1109, 8.6821, "AS206238", "Zwiebelfreunde (Known Tor Exit Node)",
                    true, true, false, 85, "[Demo Sample Fixture] Tor exit relay anonymity network",
                    "DEMO_FIXTURE", "Bundled Demo Sample (Offline Presentation Fixture)", 10.0, Instant.now().toString()
            ),
            "105.112.44.89", new GeoData(
                    "105.112.44.89", "Lagos", "Lagos State", "Nigeria", "NG",
                    6.5244, 3.3792, "AS29465", "MTN Nigeria Communications",
                    false, false, false, 75, "[Demo Sample Fixture] Origin network for sample BEC financial wire scenario",
                    "DEMO_FIXTURE", "Bundled Demo Sample (Offline Presentation Fixture)", 50.0, Instant.now().toString()
            ),
            "45.142.122.18", new GeoData(
                    "45.142.122.18", "Amsterdam", "North Holland", "Netherlands", "NL",
                    52.3676, 4.9041, "AS49870", "Albacore IT / Offshore VPS Hosting",
                    true, false, false, 65, "[Demo Sample Fixture] Offshore intermediate proxy relay",
                    "DEMO_FIXTURE", "Bundled Demo Sample (Offline Presentation Fixture)", 20.0, Instant.now().toString()
            ),
            "89.248.165.70", new GeoData(
                    "89.248.165.70", "Paris", "Île-de-France", "France", "FR",
                    48.8566, 2.3522, "AS16276", "OVH SAS Cloud Infrastructure",
                    true, false, false, 45, "[Demo Sample Fixture] Sample banking spoof hosting VPS",
                    "DEMO_FIXTURE", "Bundled Demo Sample (Offline Presentation Fixture)", 15.0, Instant.now().toString()
            ),
            "14.139.58.20", new GeoData(
                    "14.139.58.20", "New Delhi", "Delhi", "India", "IN",
                    28.6139, 77.2090, "AS9824", "National Knowledge Network (NKN) / ERNET India",
                    false, false, false, 5, "[Demo Sample Fixture] Indian Academic / Government Secure Gateway",
                    "DEMO_FIXTURE", "Bundled Demo Sample (Offline Presentation Fixture)", 10.0, Instant.now().toString()
            ),
            "14.139.1.50", new GeoData(
                    "14.139.1.50", "New Delhi", "Delhi", "India", "IN",
                    28.6139, 77.2090, "AS9824", "National Knowledge Network (NKN) / ERNET India",
                    false, false, false, 5, "[Demo Sample Fixture] Indian Academic / Government Secure Gateway",
                    "DEMO_FIXTURE", "Bundled Demo Sample (Offline Presentation Fixture)", 10.0, Instant.now().toString()
            ),
            "49.36.12.105", new GeoData(
                    "49.36.12.105", "Mumbai", "Maharashtra", "India", "IN",
                    19.0760, 72.8777, "AS55836", "Reliance Jio Infocomm Limited",
                    false, false, false, 15, "[Demo Sample Fixture] Domestic Indian recipient boundary gateway",
                    "DEMO_FIXTURE", "Bundled Demo Sample (Offline Presentation Fixture)", 15.0, Instant.now().toString()
            ),
            "122.160.88.14", new GeoData(
                    "122.160.88.14", "Hyderabad", "Telangana", "India", "IN",
                    17.3850, 78.4867, "AS24560", "Bharti Airtel Limited Telecommunications",
                    false, false, false, 15, "[Demo Sample Fixture] Domestic Indian recipient boundary gateway",
                    "DEMO_FIXTURE", "Bundled Demo Sample (Offline Presentation Fixture)", 15.0, Instant.now().toString()
            )
    );

    private final Map<String, GeoData> cache = new ConcurrentHashMap<>();
    private final ObjectMapper mapper = new ObjectMapper();
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3))
            .build();

    public GeoData resolve(String ipStr) {
        if (ipStr == null || ipStr.isBlank()) {
            return GeoData.unknown("0.0.0.0", "Missing or empty IP address", "UNAVAILABLE");
        }
        String cleanIp = ipStr.trim().replaceAll("[\\[\\]()]", "");

        // 1. Check for private, loopback, or reserved address space (RFC 1918, RFC 6598, RFC 4193, etc.)
        if (isPrivateOrLoopback(cleanIp)) {
            return GeoData.privateSubnet(cleanIp);
        }

        // 2. Check bundled demo sample fixtures (isolated to exact sample IPs only)
        GeoData fixture = DEMO_FIXTURES.get(cleanIp);
        if (fixture != null) {
            return fixture;
        }

        // 3. Resolve live from maintained data source (ip-api.com) with caching
        return cache.computeIfAbsent(cleanIp, this::resolveIpLive);
    }

    /**
     * Comprehensive IPv4 & IPv6 private, loopback, link-local, and reserved space check.
     */
    public boolean isPrivateOrLoopback(String ip) {
        if (ip == null || ip.isBlank()) return true;
        String clean = ip.trim().replaceAll("[\\[\\]()]", "");
        if ("localhost".equalsIgnoreCase(clean) || "0.0.0.0".equals(clean) || "::".equals(clean) || "::1".equals(clean)) {
            return true;
        }
        try {
            InetAddress addr = InetAddress.getByName(clean);
            if (addr.isLoopbackAddress() || addr.isSiteLocalAddress() || addr.isLinkLocalAddress()
                    || addr.isMulticastAddress() || addr.isAnyLocalAddress()) {
                return true;
            }
            if (addr instanceof Inet4Address) {
                byte[] b = addr.getAddress();
                int b0 = b[0] & 0xFF;
                int b1 = b[1] & 0xFF;
                // 10.0.0.0/8
                if (b0 == 10) return true;
                // 172.16.0.0/12
                if (b0 == 172 && (b1 >= 16 && b1 <= 31)) return true;
                // 192.168.0.0/16
                if (b0 == 192 && b1 == 168) return true;
                // 127.0.0.0/8
                if (b0 == 127) return true;
                // 100.64.0.0/10 (Carrier Grade NAT RFC 6598)
                if (b0 == 100 && (b1 >= 64 && b1 <= 127)) return true;
                // 169.254.0.0/16 (Link Local RFC 3927)
                if (b0 == 169 && b1 == 254) return true;
                // 198.18.0.0/15 (Benchmarking RFC 2544)
                if (b0 == 198 && (b1 == 18 || b1 == 19)) return true;
                // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (TEST-NET-1, 2, 3)
                if (b0 == 192 && b1 == 0 && (b[2] & 0xFF) == 2) return true;
                if (b0 == 198 && b1 == 51 && (b[2] & 0xFF) == 100) return true;
                if (b0 == 203 && b1 == 0 && (b[2] & 0xFF) == 113) return true;
                // 224.0.0.0/4 (Multicast), 240.0.0.0/4 (Reserved RFC 1112)
                if (b0 >= 224) return true;
                // 0.0.0.0/8 (This network RFC 1122)
                if (b0 == 0) return true;
            } else if (addr instanceof Inet6Address) {
                byte[] b = addr.getAddress();
                // Unique Local Address (ULA) fc00::/7 (RFC 4193)
                if ((b[0] & 0xFE) == 0xFC) return true;
                // Link-local unicast fe80::/10 (RFC 4291)
                if ((b[0] & 0xFF) == 0xFE && (b[1] & 0xC0) == 0x80) return true;
                // Discard prefix 100::/64 (RFC 6666)
                if ((b[0] & 0xFF) == 0x01 && (b[1] & 0xFF) == 0x00) return true;
                // Documentation 2001:db8::/32 (RFC 3849)
                if ((b[0] & 0xFF) == 0x20 && (b[1] & 0xFF) == 0x01 && (b[2] & 0xFF) == 0x0D && (b[3] & 0xFF) == 0xB8) return true;
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Real-time IP geolocation via ip-api.com.
     * When unresolvable, rate-limited, or timing out, returns explicit UNAVAILABLE status.
     * Never fabricates coordinates or geographic locations.
     */
    private GeoData resolveIpLive(String ip) {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create("http://ip-api.com/json/" + ip
                            + "?fields=status,message,country,countryCode,region,regionName,city,lat,lon,isp,org,as,proxy,hosting"))
                    .timeout(Duration.ofSeconds(3))
                    .header("User-Agent", "CyberShield-EmailForensics/1.0")
                    .GET()
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());

            if (resp.statusCode() == 429) {
                log.warn("ip-api.com rate limit reached for {}", ip);
                return GeoData.unknown(ip, "Rate limit reached on geolocation provider (45 req/min)", "RATE_LIMITED");
            }

            if (resp.statusCode() == 200) {
                JsonNode json = mapper.readTree(resp.body());
                String status = json.path("status").asText();

                if ("success".equalsIgnoreCase(status)) {
                    boolean isDatacenter = json.path("hosting").asBoolean(false);
                    boolean isProxy = json.path("proxy").asBoolean(false);
                    String asn = json.path("as").asText("AS-UNKNOWN");
                    String isp = json.path("isp").asText(json.path("org").asText("Unknown Network Operator"));

                    double rawLat = json.path("lat").asDouble(0.0);
                    double rawLon = json.path("lon").asDouble(0.0);
                    Double lat = (rawLat == 0.0 && rawLon == 0.0) ? null : rawLat;
                    Double lon = (rawLat == 0.0 && rawLon == 0.0) ? null : rawLon;

                    int risk = 0;
                    String reason = "Live relay network lookup (ip-api.com)";
                    if (isProxy) {
                        risk = 60;
                        reason = "Provider flags IP as proxy/VPN/anonymising infrastructure";
                    } else if (isDatacenter) {
                        risk = 30;
                        reason = "Provider identifies IP within datacenter/cloud hosting range";
                    }

                    return new GeoData(
                            ip,
                            json.path("city").asText("Unknown City"),
                            json.path("regionName").asText("Unknown Region"),
                            json.path("country").asText("Unknown Country"),
                            json.path("countryCode").asText("XX"),
                            lat,
                            lon,
                            asn,
                            isp,
                            isDatacenter,
                            isProxy,
                            false,
                            risk,
                            reason,
                            "RESOLVED",
                            "ip-api.com (Live Public Relay Geolocation)",
                            null,
                            Instant.now().toString()
                    );
                } else {
                    String msg = json.path("message").asText("Lookup unresolvable");
                    if (msg.toLowerCase().contains("rate limit")) {
                        return GeoData.unknown(ip, "Provider rate limit exceeded", "RATE_LIMITED");
                    }
                    if (msg.toLowerCase().contains("private") || msg.toLowerCase().contains("reserved")) {
                        return GeoData.privateSubnet(ip);
                    }
                    return GeoData.unknown(ip, "Provider response: " + msg, "UNAVAILABLE");
                }
            }
        } catch (Exception e) {
            log.warn("Live geolocation lookup unavailable for {}: {}", ip, e.getMessage());
        }
        // Explicitly return UNAVAILABLE without fabricating coordinates or city locations
        return GeoData.unknown(ip, "Live geolocation service timed out or unavailable", "UNAVAILABLE");
    }
}
