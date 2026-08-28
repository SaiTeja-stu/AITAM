package com.cybershield.web;

import com.cybershield.scan.ScanRecord;
import com.cybershield.scan.ScanRecordRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/history")
public class HistoryController {

    private final ScanRecordRepository scans;

    public HistoryController(ScanRecordRepository scans) {
        this.scans = scans;
    }

    public record HistoryItem(String reportId, String type, int riskScore, String riskLevel,
                              String priority, int confidence, String snippet, Instant analyzedAt) {}

    /** The caller's own recent analyses (hot tier: last ~30 days). */
    @GetMapping
    public Map<String, Object> history(@RequestParam(defaultValue = "0") int page,
                                       @RequestParam(defaultValue = "20") int size) {
        int safeSize = Math.min(Math.max(size, 1), 100);
        int safePage = Math.max(page, 0);
        String owner = CurrentUser.id();
        Page<ScanRecord> result = scans.findByOwnerIdOrderByCreatedAtDesc(
                owner, PageRequest.of(safePage, safeSize));
        List<HistoryItem> items = result.map(r -> new HistoryItem(
                r.getId(), r.getType().name(), r.getRiskScore(), r.getRiskLevel().name(),
                r.getPriority(), r.getConfidence(), r.getSnippet(), r.getCreatedAt())).getContent();
        return Map.of(
                "items", items,
                "page", safePage,
                "size", safeSize,
                "totalElements", result.getTotalElements(),
                "totalPages", result.getTotalPages());
    }
}
