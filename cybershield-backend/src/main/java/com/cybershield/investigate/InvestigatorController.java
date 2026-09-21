package com.cybershield.investigate;

import com.cybershield.common.Hashing;
import com.cybershield.domain.RiskLevel;
import com.cybershield.intel.IndicatorType;
import com.cybershield.report.ThreatReport;
import com.cybershield.report.ThreatReportRepository;
import com.cybershield.scan.ScanRecord;
import com.cybershield.scan.ScanRecordRepository;
import com.cybershield.security.JwtService;
import com.cybershield.url.UrlParts;
import com.cybershield.web.CurrentUser;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Cyber-cell investigator console (backend API only - see /investigate.html for
 * the browser UI). An investigator searches one suspect indicator (a domain, a
 * URL, a UPI VPA, a phone number) and gets back a cross-user CORRELATION
 * PATTERN - victim count, first/last seen, risk trend, report status counts -
 * never a victim's identity, message content, or contact details. Every search
 * is written to {@link InvestigatorAuditLog} for accountability.
 */
@RestController
@RequestMapping("/api/v1/investigate")
@PreAuthorize("hasRole('INVESTIGATOR')")
public class InvestigatorController {

    private final ThreatReportRepository reports;
    private final ScanRecordRepository scans;
    private final InvestigatorAuditLogRepository audit;
    private final Hashing hashing;

    public InvestigatorController(ThreatReportRepository reports, ScanRecordRepository scans,
                                  InvestigatorAuditLogRepository audit, Hashing hashing) {
        this.reports = reports;
        this.scans = scans;
        this.audit = audit;
        this.hashing = hashing;
    }

    public record SearchResult(
            String indicatorType, String indicatorValueDisplay,
            int victimCount, int totalHits,
            Instant firstSeen, Instant lastSeen,
            Map<String, Long> riskLevelBreakdown,
            Map<String, Long> reportStatusBreakdown,
            int confirmedReportCount) {}

    @GetMapping("/search")
    public ResponseEntity<?> search(@RequestParam String type, @RequestParam String value,
                                    HttpServletRequest http) {
        String raw = value == null ? "" : value.trim();
        if (raw.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("detail", "Provide an indicator value to search."));
        }

        IndicatorType kind;
        String normalized;
        String display;
        try {
            switch (type.trim().toUpperCase(Locale.ROOT)) {
                case "DOMAIN" -> { kind = IndicatorType.DOMAIN; normalized = raw.toLowerCase(Locale.ROOT); display = normalized; }
                case "URL" -> {
                    String host = UrlParts.parse(raw).map(UrlParts::host).orElse(null);
                    if (host == null) return ResponseEntity.badRequest().body(Map.of("detail", "Could not parse a domain out of that URL."));
                    kind = IndicatorType.DOMAIN; normalized = host.toLowerCase(Locale.ROOT); display = normalized;
                }
                case "VPA" -> { kind = IndicatorType.VPA_HASH; normalized = hashing.hmac(raw); display = maskVpa(raw); }
                case "PHONE" -> { kind = IndicatorType.PHONE; normalized = hashing.hmac(raw); display = maskPhone(raw); }
                default -> { return ResponseEntity.badRequest().body(Map.of("detail", "type must be DOMAIN, URL, VPA, or PHONE.")); }
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("detail", "Could not read that indicator."));
        }

        List<ThreatReport> matchedReports = reports.findByIndicatorTypeAndIndicatorValue(kind, normalized);

        // Corroborate against passive (non-reported) scans too - domain/phone fragments
        // survive PII redaction in the snippet, VPA/content hashes never appear in plain text.
        String snippetNeedle = (kind == IndicatorType.DOMAIN) ? normalized : null;
        List<ScanRecord> matchedScans = snippetNeedle == null
                ? List.of() : scans.searchBySnippetContains(snippetNeedle);

        int totalHits = matchedReports.size() + matchedScans.size();

        Set<String> distinctVictims = new HashSet<>();
        matchedReports.forEach(r -> { if (r.getReporterId() != null) distinctVictims.add("r:" + r.getReporterId()); });
        matchedScans.forEach(s -> { if (s.getOwnerId() != null) distinctVictims.add("s:" + s.getOwnerId()); });

        Instant first = null, last = null;
        Map<String, Long> riskBreakdown = new TreeMap<>();
        for (ScanRecord s : matchedScans) {
            riskBreakdown.merge(s.getRiskLevel().name(), 1L, Long::sum);
            if (first == null || s.getCreatedAt().isBefore(first)) first = s.getCreatedAt();
            if (last == null || s.getCreatedAt().isAfter(last)) last = s.getCreatedAt();
        }
        for (ThreatReport r : matchedReports) {
            if (first == null || r.getCreatedAt().isBefore(first)) first = r.getCreatedAt();
            if (last == null || r.getCreatedAt().isAfter(last)) last = r.getCreatedAt();
        }

        Map<String, Long> statusBreakdown = matchedReports.stream()
                .collect(Collectors.groupingBy(r -> r.getStatus().name(), TreeMap::new, Collectors.counting()));
        long confirmed = matchedReports.stream().filter(r -> r.getStatus() == ThreatReport.Status.CONFIRMED).count();

        SearchResult result = new SearchResult(
                kind.name(), display,
                distinctVictims.size(), totalHits,
                first, last,
                riskBreakdown, statusBreakdown, (int) confirmed);

        logSearch(kind.name(), display, totalHits, http);
        return ResponseEntity.ok(result);
    }

    @GetMapping("/history")
    public Map<String, Object> myHistory(@RequestParam(defaultValue = "0") int page,
                                         @RequestParam(defaultValue = "20") int size) {
        JwtService.AuthenticatedUser me = CurrentUser.principal();
        var p = audit.findByInvestigatorIdOrderBySearchedAtDesc(me.userId(),
                org.springframework.data.domain.PageRequest.of(Math.max(page, 0), Math.min(Math.max(size, 1), 100)));
        return Map.of("items", p.getContent(), "page", p.getNumber(), "totalPages", p.getTotalPages());
    }

    private void logSearch(String type, String value, int resultCount, HttpServletRequest http) {
        JwtService.AuthenticatedUser me = CurrentUser.principal();
        if (me == null) return;
        InvestigatorAuditLog log = new InvestigatorAuditLog();
        log.setId(UUID.randomUUID().toString());
        log.setInvestigatorId(me.userId());
        log.setInvestigatorUsername(me.username());
        log.setIndicatorType(type);
        log.setIndicatorValue(value);
        log.setResultCount(resultCount);
        log.setRequestIp(ip(http));
        audit.save(log);
    }

    private static String ip(HttpServletRequest req) {
        String xff = req.getHeader("X-Forwarded-For");
        return (xff != null && !xff.isBlank()) ? xff.split(",")[0].trim() : req.getRemoteAddr();
    }

    private static String maskVpa(String vpa) {
        int at = vpa.indexOf('@');
        if (at <= 1) return "***";
        return vpa.charAt(0) + "***" + vpa.substring(at);
    }

    private static String maskPhone(String phone) {
        String digits = phone.replaceAll("\\D", "");
        return digits.length() <= 4 ? "****" : "******" + digits.substring(digits.length() - 4);
    }
}
