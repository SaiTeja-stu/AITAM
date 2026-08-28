package com.cybershield.web;

import com.cybershield.report.ThreatReport;
import com.cybershield.report.ReportService;
import com.cybershield.scan.ScanRecord;
import com.cybershield.scan.ScanRecordRepository;
import com.cybershield.domain.RiskLevel;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/** Dashboard / moderation API. Everything here is ADMIN-only (enforced in SecurityConfig + @PreAuthorize). */
@RestController
@RequestMapping("/api/v1/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final ReportService reports;
    private final ScanRecordRepository scans;

    public AdminController(ReportService reports, ScanRecordRepository scans) {
        this.reports = reports;
        this.scans = scans;
    }

    public record ReportView(String id, String type, String snippet, String indicatorType,
                             String indicatorValue, String note, String status, Instant createdAt) {}

    public record ScanView(String reportId, String type, int riskScore, String riskLevel,
                           String priority, int confidence, boolean verified, String snippet,
                           Instant analyzedAt) {}

    @GetMapping("/reports")
    public Map<String, Object> listReports(@RequestParam(required = false) String status,
                                           @RequestParam(defaultValue = "0") int page,
                                           @RequestParam(defaultValue = "20") int size) {
        ThreatReport.Status st = null;
        if (status != null && !status.isBlank()) {
            try { st = ThreatReport.Status.valueOf(status.toUpperCase()); }
            catch (IllegalArgumentException ignored) { }
        }
        Page<ThreatReport> p = reports.list(st, PageRequest.of(clampPage(page), clampSize(size)));
        List<ReportView> items = p.map(r -> new ReportView(
                r.getId(), r.getType().name(), r.getSnippet(),
                r.getIndicatorType() == null ? null : r.getIndicatorType().name(),
                r.getIndicatorValue(), r.getReporterNote(),
                r.getStatus().name(), r.getCreatedAt())).getContent();
        return pageBody(items, p);
    }

    @PostMapping("/reports/{id}/confirm")
    public ResponseEntity<Map<String, Object>> confirm(@PathVariable String id) {
        return reports.confirm(id)
                ? ResponseEntity.ok(Map.of("id", id, "status", "CONFIRMED"))
                : ResponseEntity.notFound().build();
    }

    @PostMapping("/reports/{id}/reject")
    public ResponseEntity<Map<String, Object>> reject(@PathVariable String id) {
        return reports.reject(id)
                ? ResponseEntity.ok(Map.of("id", id, "status", "REJECTED"))
                : ResponseEntity.notFound().build();
    }

    /** Recent analyses across all users - the dashboard priority queue. */
    @GetMapping("/scans")
    public Map<String, Object> recentScans(@RequestParam(required = false) String level,
                                           @RequestParam(defaultValue = "0") int page,
                                           @RequestParam(defaultValue = "25") int size) {
        PageRequest pr = PageRequest.of(clampPage(page), clampSize(size));
        Page<ScanRecord> p;
        if (level != null && !level.isBlank()) {
            try {
                p = scans.findByRiskLevelOrderByCreatedAtDesc(RiskLevel.valueOf(level.toUpperCase()), pr);
            } catch (IllegalArgumentException e) {
                p = scans.findAllByOrderByCreatedAtDesc(pr);
            }
        } else {
            p = scans.findAllByOrderByCreatedAtDesc(pr);
        }
        List<ScanView> items = p.map(r -> new ScanView(
                r.getId(), r.getType().name(), r.getRiskScore(), r.getRiskLevel().name(),
                r.getPriority(), r.getConfidence(), r.isVerified(), r.getSnippet(),
                r.getCreatedAt())).getContent();
        return pageBody(items, p);
    }

    private static int clampPage(int p) { return Math.max(p, 0); }
    private static int clampSize(int s) { return Math.min(Math.max(s, 1), 100); }

    private static Map<String, Object> pageBody(List<?> items, Page<?> p) {
        return Map.of(
                "items", items,
                "page", p.getNumber(),
                "size", p.getSize(),
                "totalElements", p.getTotalElements(),
                "totalPages", p.getTotalPages());
    }
}
