package com.cybershield.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Read-only "where does the data live" view for the admin dashboard: the registered users
 * (with consent record and activity counts) and a map of every table / file the platform stores.
 * Emails and IPs are masked; password hashes and one-time codes are never returned.
 */
@RestController
@RequestMapping("/api/v1/admin")
@PreAuthorize("hasRole('ADMIN')")
public class DataOverviewController {

    private static final Map<String, String> PURPOSE = Map.of(
            "user_account", "Accounts: user id, username, email, role, consent record. Password kept only as a one-way hash.",
            "otp_challenge", "Email verification and password-reset codes. Stored only as keyed hashes; expire in 15 minutes.",
            "scan_record", "Scan history: redacted snippet, content hash and verdict, tagged with the owner's user id.",
            "threat_report", "Scam reports submitted by users, waiting for or finished with moderation.",
            "email_incident_record", "Email forensic incidents: sender domain, origin IP, risk tier and evidence hash.",
            "investigator_audit_log", "Who searched what in the investigator console (accountability log).");

    private final JdbcTemplate jdbc;
    private final String dbPath;
    private final String archiveDir;
    private final int retentionDays;

    public DataOverviewController(JdbcTemplate jdbc,
                                  @Value("${CYBERSHIELD_DB_PATH:./data/cybershield.db}") String dbPath,
                                  @Value("${CYBERSHIELD_ARCHIVE_DIR:./data/archive}") String archiveDir,
                                  @Value("${cybershield.hot-retention-days:30}") int retentionDays) {
        this.jdbc = jdbc;
        this.dbPath = dbPath;
        this.archiveDir = archiveDir;
        this.retentionDays = retentionDays;
    }

    @GetMapping("/users")
    public Map<String, Object> users() {
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT u.id, u.username, u.email, u.display_name, u.role, u.enabled, u.email_verified, "
                        + "u.terms_version, u.terms_accepted_at, u.created_at, u.last_login_at, u.last_login_ip, "
                        + "(SELECT COUNT(*) FROM scan_record s WHERE s.owner_id = u.id) AS scans, "
                        + "(SELECT COUNT(*) FROM threat_report t WHERE t.reporter_id = u.id) AS reports "
                        + "FROM user_account u ORDER BY u.created_at DESC LIMIT 500");
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> r : rows) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", r.get("id"));
            m.put("username", r.get("username"));
            m.put("displayName", r.get("display_name"));
            m.put("email", maskEmail(str(r.get("email"))));
            m.put("role", r.get("role"));
            m.put("enabled", truthy(r.get("enabled")));
            m.put("emailVerified", truthy(r.get("email_verified")));
            m.put("termsVersion", r.get("terms_version"));
            m.put("termsAcceptedAt", ts(r.get("terms_accepted_at")));
            m.put("createdAt", ts(r.get("created_at")));
            m.put("lastLoginAt", ts(r.get("last_login_at")));
            m.put("lastLoginIp", maskIp(str(r.get("last_login_ip"))));
            m.put("scans", num(r.get("scans")));
            m.put("reports", num(r.get("reports")));
            out.add(m);
        }
        return Map.of("total", out.size(), "items", out);
    }

    @GetMapping("/storage")
    public Map<String, Object> storage() {
        Map<String, Object> body = new LinkedHashMap<>();

        Map<String, Object> db = new LinkedHashMap<>();
        db.put("engine", "SQLite 3 (hot tier)");
        db.put("file", dbPath);
        db.put("sizeBytes", size(Path.of(dbPath)));
        db.put("retentionDays", retentionDays);
        body.put("database", db);

        List<Map<String, Object>> tables = new ArrayList<>();
        List<String> names = jdbc.queryForList(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
                String.class);
        for (String n : names) {
            if (!n.matches("[a-z_]+")) continue; // names are interpolated below: allow only plain identifiers
            Map<String, Object> t = new LinkedHashMap<>();
            t.put("table", n);
            t.put("rows", jdbc.queryForObject("SELECT COUNT(*) FROM " + n, Long.class));
            t.put("holds", PURPOSE.getOrDefault(n, "Application data."));
            tables.add(t);
        }
        body.put("tables", tables);

        Map<String, Object> arch = new LinkedHashMap<>();
        arch.put("format", "Compressed JSONL logs (cold tier, forensic / ML archive)");
        arch.put("directory", archiveDir);
        long[] fc = {0, 0};
        try (Stream<Path> s = Files.walk(Path.of(archiveDir))) {
            s.filter(Files::isRegularFile).forEach(f -> {
                fc[0]++;
                fc[1] += size(f);
            });
        } catch (Exception ignored) {
            // archive folder may not exist yet
        }
        arch.put("files", fc[0]);
        arch.put("sizeBytes", fc[1]);
        body.put("archive", arch);

        body.put("notes", List.of(
                "Passwords are stored only as salted one-way hashes; one-time codes only as keyed hashes.",
                "Scan history keeps a redacted snippet and a content hash, not the full message.",
                "Emails and IP addresses are masked in this view.",
                "Hot data older than " + retentionDays + " days is pruned automatically; the archive is append-only."));
        body.put("generatedAt", Instant.now().toString());
        return body;
    }

    // ---- helpers
    private static String str(Object o) {
        return o == null ? "" : o.toString();
    }

    private static long num(Object o) {
        return o instanceof Number n ? n.longValue() : 0;
    }

    private static boolean truthy(Object o) {
        return o instanceof Number n ? n.intValue() != 0 : Boolean.parseBoolean(str(o));
    }

    private static String ts(Object o) {
        if (o == null) return null;
        if (o instanceof Number n) return Instant.ofEpochMilli(n.longValue()).toString();
        return o.toString();
    }

    private static long size(Path p) {
        try {
            return Files.size(p);
        } catch (Exception e) {
            return 0;
        }
    }

    static String maskEmail(String e) {
        int at = e.indexOf('@');
        if (at < 2) return e.isEmpty() ? "" : "***" + e.substring(Math.max(at, 0));
        return e.charAt(0) + "***" + e.substring(at);
    }

    static String maskIp(String ip) {
        if (ip.isEmpty()) return "";
        if (ip.contains(":")) { // IPv6: keep the first two groups only
            String[] g = ip.split(":");
            return g.length >= 2 ? g[0] + ":" + g[1] + ":xxxx" : "xxxx";
        }
        int dot = ip.lastIndexOf('.');
        return dot > 0 ? ip.substring(0, dot) + ".xxx" : ip;
    }
}
