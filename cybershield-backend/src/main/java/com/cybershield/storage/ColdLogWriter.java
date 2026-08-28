package com.cybershield.storage;

import com.cybershield.domain.Verdict;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Tier-2 cold store: appends one JSON line per analysis to a dedicated logger
 * ("SCAN_ARCHIVE") whose Logback appender rotates by size+date and gzips old
 * files. This is the immutable audit trail and the ML training dataset
 * (trust policy T-09). Never contains un-redacted PII.
 */
@Component
public class ColdLogWriter {

    private static final Logger ARCHIVE = LoggerFactory.getLogger("SCAN_ARCHIVE");
    private final ObjectMapper mapper;

    public ColdLogWriter(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public void write(String reportId, String type, String contentHash, String redactedSnippet,
                      Verdict v, String source, String ownerId) {
        try {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("ts", Instant.now().toString());
            row.put("report_id", reportId);
            row.put("type", type);
            row.put("content_hash", contentHash);
            row.put("snippet", redactedSnippet);
            row.put("risk_score", v.getRiskScore());
            row.put("risk_level", v.getRiskLevel() == null ? null : v.getRiskLevel().name());
            row.put("priority", v.getRiskLevel() == null ? null : v.getRiskLevel().priority());
            row.put("confidence", v.getConfidence());
            row.put("verified", v.isVerified());
            row.put("categories", v.getCategories());
            row.put("signals", v.getSignals().stream().map(s -> Map.of(
                    "id", s.policyId(), "name", s.name(),
                    "severity", s.severity().name(), "weight", s.weight())).toList());
            row.put("source", source);
            row.put("owner", ownerId);
            ARCHIVE.info(mapper.writeValueAsString(row));
        } catch (Exception e) {
            LoggerFactory.getLogger(getClass()).warn("cold-log write failed: {}", e.toString());
        }
    }
}
