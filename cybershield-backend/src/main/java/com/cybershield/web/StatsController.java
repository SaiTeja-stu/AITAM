package com.cybershield.web;

import com.cybershield.report.ThreatReport;
import com.cybershield.report.ThreatReportRepository;
import com.cybershield.scan.ScanRecordRepository;
import com.cybershield.storage.ArchiveAnalyticsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/** Dashboard aggregates (ADMIN only). Live counts from the hot tier + trends from the cold tier. */
@RestController
@RequestMapping("/api/v1/stats")
public class StatsController {

    private final ScanRecordRepository scans;
    private final ThreatReportRepository reports;
    private final ArchiveAnalyticsService analytics;

    public StatsController(ScanRecordRepository scans, ThreatReportRepository reports,
                           ArchiveAnalyticsService analytics) {
        this.scans = scans;
        this.reports = reports;
        this.analytics = analytics;
    }

    @GetMapping
    public Map<String, Object> stats() {
        Map<String, Long> byLevel = new LinkedHashMap<>();
        for (Object[] row : scans.countByRiskLevel()) {
            byLevel.put(String.valueOf(row[0]), ((Number) row[1]).longValue());
        }
        Map<String, Long> byType = new LinkedHashMap<>();
        for (Object[] row : scans.countByType()) {
            byType.put(String.valueOf(row[0]), ((Number) row[1]).longValue());
        }
        Instant since = Instant.now().minus(7, ChronoUnit.DAYS);
        Map<String, Object> out = new HashMap<>();
        out.put("totalScans", scans.count());
        out.put("scansLast7Days", scans.countByCreatedAtAfter(since));
        out.put("scansByRiskLevel", byLevel);
        out.put("scansByContentType", byType);
        out.put("reportsPending", reports.countByStatus(ThreatReport.Status.PENDING));
        out.put("reportsConfirmed", reports.countByStatus(ThreatReport.Status.CONFIRMED));
        out.put("reportsRejected", reports.countByStatus(ThreatReport.Status.REJECTED));
        return out;
    }

    @GetMapping("/trends")
    public Map<String, Object> trends() {
        return analytics.trends();
    }
}
