package com.cybershield;

import com.cybershield.security.LoginAttemptService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end security tests against a running context (SQLite in-memory).
 * Covers the security spec's Input Validation, Authentication and Injection matrices.
 * Uses java.net.http so error responses are returned, never thrown.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ApiSecurityIT {

    @LocalServerPort int port;
    @Autowired LoginAttemptService loginAttempts;

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
    private final ObjectMapper mapper = new ObjectMapper();
    private String base;

    @BeforeEach
    void setUp() {
        base = "http://localhost:" + port;
        loginAttempts.reset();
    }

    private HttpResponse<String> send(String method, String path, String body, String token) {
        try {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "application/json");
            if (token != null) b.header("Authorization", "Bearer " + token);
            b.method(method, body == null
                    ? HttpRequest.BodyPublishers.noBody()
                    : HttpRequest.BodyPublishers.ofString(body));
            return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String adminToken() {
        var r = send("POST", "/auth/login",
                "{\"login\":\"admin\",\"password\":\"admin-password-123456\"}", null);
        assertThat(r.statusCode()).isEqualTo(200);
        try {
            return mapper.readTree(r.body()).get("accessToken").asText();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String jsonString(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\r", "\\r").replace("\n", "\\n")
                .replaceAll("[\u0000-\u001f]", " ") + "\"";
    }

    // ---------- Input validation ----------

    @Test
    void rejects_empty_content() {
        var r = send("POST", "/api/v1/analyze", "{\"type\":\"URL\",\"content\":\"\"}", adminToken());
        assertThat(r.statusCode()).isEqualTo(400);
    }

    @Test
    void rejects_oversized_content() {
        String big = "x".repeat(20_001);
        var r = send("POST", "/api/v1/analyze",
                "{\"type\":\"URL\",\"content\":\"" + big + "\"}", adminToken());
        assertThat(r.statusCode()).isEqualTo(400);
    }

    @Test
    void rejects_unknown_json_properties() {
        var r = send("POST", "/api/v1/analyze",
                "{\"type\":\"URL\",\"content\":\"http://a.com\",\"admin\":true}", adminToken());
        assertThat(r.statusCode()).isEqualTo(400);
    }

    @Test
    void rejects_malformed_json() {
        var r = send("POST", "/api/v1/analyze", "{not json", adminToken());
        assertThat(r.statusCode()).isEqualTo(400);
    }

    @Test
    void rejects_invalid_enum_value() {
        var r = send("POST", "/api/v1/analyze", "{\"type\":\"HACK\",\"content\":\"x\"}", adminToken());
        assertThat(r.statusCode()).isEqualTo(400);
    }

    @Test
    void malformed_qr_and_weird_chars_do_not_500() {
        String token = adminToken();
        for (String c : List.of("upi://pay?%%%", "\u0001\u0002", "://///", "\\x41\\x42")) {
            var r = send("POST", "/api/v1/analyze",
                    "{\"type\":\"QR\",\"content\":" + jsonString(c) + "}", token);
            assertThat(r.statusCode()).isLessThan(500);
        }
    }

    // ---------- Authentication ----------

    @Test
    void missing_token_is_401() {
        var r = send("POST", "/api/v1/analyze",
                "{\"type\":\"URL\",\"content\":\"http://a.com\"}", null);
        assertThat(r.statusCode()).isEqualTo(401);
    }

    @Test
    void invalid_and_modified_tokens_are_401() {
        String good = adminToken();
        String modified = good.substring(0, good.length() - 3) + "aaa";
        for (String t : List.of("not.a.token", "Bearerx", modified)) {
            var r = send("GET", "/api/v1/history", null, t);
            assertThat(r.statusCode()).isEqualTo(401);
        }
    }

    @Test
    void expired_token_is_401() throws Exception {
        String token = adminToken();           // ttl is 2s in test config
        Thread.sleep(2500);
        var r = send("GET", "/api/v1/history", null, token);
        assertThat(r.statusCode()).isEqualTo(401);
    }

    @Test
    void wrong_password_gives_generic_message() {
        var r = send("POST", "/auth/login",
                "{\"login\":\"admin\",\"password\":\"wrong-password-123\"}", null);
        assertThat(r.statusCode()).isEqualTo(401);
        assertThat(r.body().toLowerCase()).contains("invalid");
    }

    @Test
    void account_enumeration_parity_between_known_and_unknown_user() {
        var known = send("POST", "/auth/login",
                "{\"login\":\"admin\",\"password\":\"bad-password-000\"}", null);
        var unknown = send("POST", "/auth/login",
                "{\"login\":\"ghost-user\",\"password\":\"bad-password-000\"}", null);
        assertThat(known.statusCode()).isEqualTo(unknown.statusCode());
        assertThat(known.body()).isEqualTo(unknown.body());
    }

    @Test
    void repeated_failures_trigger_lockout() {
        int last = 0;
        for (int i = 0; i < 6; i++) {
            last = send("POST", "/auth/login",
                    "{\"login\":\"lockme\",\"password\":\"bad-password-000\"}", null).statusCode();
        }
        assertThat(last).isEqualTo(429);
    }

    @Test
    void register_response_is_generic_and_does_not_leak_existing_account() {
        var fresh = send("POST", "/auth/register",
                "{\"email\":\"fresh-user@example.com\",\"username\":\"freshu\",\"password\":\"averylongpassword12\"}", null);
        var taken = send("POST", "/auth/register",
                "{\"email\":\"admin@cybershield.test\",\"username\":\"admin\",\"password\":\"averylongpassword12\"}", null);
        assertThat(fresh.statusCode()).isEqualTo(taken.statusCode());
        assertThat(fresh.body()).isEqualTo(taken.body());
    }

    @Test
    void non_admin_cannot_reach_stats() {
        send("POST", "/auth/register",
                "{\"email\":\"plainuser@example.com\",\"username\":\"plainuser\",\"password\":\"averylongpassword12\"}", null);
        var login = send("POST", "/auth/login",
                "{\"login\":\"plainuser\",\"password\":\"averylongpassword12\"}", null);
        String token;
        try { token = mapper.readTree(login.body()).get("accessToken").asText(); }
        catch (Exception e) { throw new RuntimeException(e); }
        var r = send("GET", "/api/v1/stats", null, token);
        assertThat(r.statusCode()).isEqualTo(403);
    }

    // ---------- Injection ----------

    @Test
    void injection_payloads_are_handled_without_error_or_leak() {
        List<String> payloads = List.of(
                "' OR '1'='1", "'; DROP TABLE scan_record;--",
                "<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>",
                "../../../../etc/passwd", "%2e%2e%2f%2e%2e%2f",
                "; ls -la", "$(reboot)", "`id`", "| cat /etc/shadow",
                "test\r\nSet-Cookie: evil=1", "http://169.254.169.254/latest/meta-data/");
        String token = adminToken();
        for (String p : payloads) {
            var r = send("POST", "/api/v1/analyze",
                    "{\"type\":\"SMS\",\"content\":" + jsonString(p) + "}", token);
            assertThat(r.statusCode()).as("payload: %s", p).isLessThan(500);
            assertThat(r.body()).doesNotContain("SQLException", "org.hibernate", "SQLITE_ERROR");
        }
    }

    // ---------- Analysis behaviour ----------

    @Test
    void detects_receive_money_qr_scam() throws Exception {
        var r = send("POST", "/api/v1/analyze",
                "{\"type\":\"SMS\",\"content\":\"Scan this QR to receive your refund of Rs 5000 immediately\"}",
                adminToken());
        assertThat(r.statusCode()).isEqualTo(200);
        JsonNode body = mapper.readTree(r.body());
        assertThat(body.get("riskLevel").asText()).isIn("HIGH_RISK", "MALICIOUS");
        assertThat(body.get("explanation").asText().toLowerCase()).contains("never credits your account");
    }

    @Test
    void blocklisted_domain_is_malicious_and_not_called_verified() throws Exception {
        var r = send("POST", "/api/v1/analyze",
                "{\"type\":\"URL\",\"content\":\"https://paypa1-verify.com/login\"}", adminToken());
        JsonNode body = mapper.readTree(r.body());
        assertThat(body.get("riskLevel").asText()).isEqualTo("MALICIOUS");
        assertThat(body.get("verified").asBoolean()).isFalse();
        assertThat(body.get("wording").asText()).isNotEqualToIgnoringCase("verified");
    }

    @Test
    void education_modules_are_public() {
        var r = send("GET", "/api/v1/education/modules", null, null);
        assertThat(r.statusCode()).isEqualTo(200);
        assertThat(r.body()).contains("upi-qr-safety");
    }

    // ---------- Admin / dashboard ----------

    @Test
    void admin_can_list_reports_and_recent_scans() {
        String token = adminToken();
        assertThat(send("GET", "/api/v1/admin/reports?status=PENDING", null, token).statusCode()).isEqualTo(200);
        assertThat(send("GET", "/api/v1/admin/scans", null, token).statusCode()).isEqualTo(200);
        assertThat(send("GET", "/api/v1/stats/trends", null, token).statusCode()).isEqualTo(200);
    }

    @Test
    void non_admin_cannot_list_reports() {
        send("POST", "/auth/register",
                "{\"email\":\"plainuser2@example.com\",\"username\":\"plainuser2\",\"password\":\"averylongpassword12\"}", null);
        var login = send("POST", "/auth/login",
                "{\"login\":\"plainuser2\",\"password\":\"averylongpassword12\"}", null);
        String token;
        try { token = mapper.readTree(login.body()).get("accessToken").asText(); }
        catch (Exception e) { throw new RuntimeException(e); }
        assertThat(send("GET", "/api/v1/admin/reports", null, token).statusCode()).isEqualTo(403);
    }

    @Test
    void report_then_confirm_flow_works() throws Exception {
        String token = adminToken();
        var submit = send("POST", "/api/v1/report",
                "{\"type\":\"URL\",\"content\":\"https://brand-new-scam-site-xyz.tk/login\",\"note\":\"fake bank\"}", token);
        assertThat(submit.statusCode()).isEqualTo(201);
        String reportId = mapper.readTree(submit.body()).get("reportId").asText();
        var confirm = send("POST", "/api/v1/admin/reports/" + reportId + "/confirm", null, token);
        assertThat(confirm.statusCode()).isEqualTo(200);
        // now that domain should be treated as blocked
        var check = send("POST", "/api/v1/analyze",
                "{\"type\":\"URL\",\"content\":\"https://brand-new-scam-site-xyz.tk/anything\"}", token);
        assertThat(mapper.readTree(check.body()).get("riskLevel").asText()).isEqualTo("MALICIOUS");
    }

    // ---------- URL scanner endpoint (spec-shaped) ----------

    @Test
    void analyze_url_endpoint_requires_auth() throws Exception {
        var r = send("POST", "/api/analyze-url", "{\"url\":\"https://example.com\"}", null);
        assertThat(r.statusCode()).isEqualTo(401);
    }

    @Test
    void analyze_url_endpoint_returns_evidence_and_five_level_scale() throws Exception {
        var r = send("POST", "/api/analyze-url",
                "{\"url\":\"http://paypa1-verify-login.tk/webscr?cmd=_login-run\"}", adminToken());
        assertThat(r.statusCode()).isEqualTo(200);
        JsonNode b = mapper.readTree(r.body());
        assertThat(b.get("risk_score").asInt()).isGreaterThan(20);
        assertThat(b.get("risk_level").asText())
                .isIn("LOW_RISK", "SUSPICIOUS", "HIGH_RISK", "CRITICAL");
        assertThat(b.get("indicators")).isNotEmpty();
        assertThat(b.get("recommendations")).isNotEmpty();
        assertThat(b.has("threat_intelligence")).isTrue();
        // the ML model must have contributed a signal
        boolean mlFired = false;
        for (JsonNode ind : b.get("indicators")) {
            if ("ML_URL_RISK".equals(ind.path("type").asText())) mlFired = true;
        }
        assertThat(mlFired).as("ML_URL_RISK indicator present").isTrue();
    }

    @Test
    void analyze_url_endpoint_flags_egregious_url_high() throws Exception {
        var r = send("POST", "/api/analyze-url",
                "{\"url\":\"https://paypal.com@secure-login-verify-account.tk/kyc/confirm\"}", adminToken());
        JsonNode b = mapper.readTree(r.body());
        assertThat(b.get("risk_score").asInt()).isGreaterThanOrEqualTo(50);
        assertThat(b.get("risk_level").asText()).isIn("SUSPICIOUS", "HIGH_RISK", "CRITICAL");
    }

    @Test
    void analyze_url_endpoint_stays_calm_on_a_clean_link() throws Exception {
        var r = send("POST", "/api/analyze-url", "{\"url\":\"https://www.google.com\"}", adminToken());
        JsonNode b = mapper.readTree(r.body());
        assertThat(b.get("risk_level").asText()).isIn("SAFE", "LOW_RISK");
        assertThat(b.get("risk_score").asInt()).isLessThan(25);
    }

    @Test
    void analyze_url_rejects_blank() throws Exception {
        var r = send("POST", "/api/analyze-url", "{\"url\":\"\"}", adminToken());
        assertThat(r.statusCode()).isEqualTo(400);
    }

    // ---------- Email scanner ----------

    private String emailFixture(String name) throws Exception {
        try (var in = getClass().getResourceAsStream("/emails/" + name)) {
            return new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        }
    }

    @Test
    void analyze_email_flags_phishing_with_auth_and_sender_evidence() throws Exception {
        String body = mapper.writeValueAsString(java.util.Map.of("raw", emailFixture("phishing_paypal.eml")));
        var r = send("POST", "/api/analyze-email", body, adminToken());
        assertThat(r.statusCode()).isEqualTo(200);
        JsonNode b = mapper.readTree(r.body());

        assertThat(b.get("risk_score").asInt()).isGreaterThanOrEqualTo(60);
        assertThat(b.get("verdict").asText()).isEqualTo("PHISHING");
        assertThat(b.get("authentication").get("dmarc").asText()).isEqualTo("FAIL");
        assertThat(b.get("sender").get("domain").asText()).isEqualTo("paypa1-account-verify.tk");

        java.util.Set<String> types = new java.util.HashSet<>();
        for (JsonNode i : b.get("indicators")) types.add(i.get("type").asText());
        assertThat(types).contains("FAILED_EMAIL_AUTH", "DISPLAY_NAME_SPOOF");
    }

    @Test
    void analyze_email_stays_calm_on_a_genuine_message() throws Exception {
        String body = mapper.writeValueAsString(java.util.Map.of("raw", emailFixture("genuine_amazon.eml")));
        var r = send("POST", "/api/analyze-email", body, adminToken());
        JsonNode b = mapper.readTree(r.body());
        assertThat(b.get("risk_level").asText()).isIn("SAFE", "LOW_RISK");
        assertThat(b.get("verdict").asText()).isIn("LOOKS_LEGITIMATE", "SUSPICIOUS");
        assertThat(b.get("authentication").get("spf").asText()).isEqualTo("PASS");
    }
}
