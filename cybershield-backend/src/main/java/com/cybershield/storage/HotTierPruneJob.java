package com.cybershield.storage;

import com.cybershield.scan.ScanRecordRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;

/**
 * Keeps the SQLite hot tier small: every night, delete scan rows older than the
 * retention window. They are already durably recorded in the cold JSONL log, so
 * this is a pure delete (no migration, no data loss).
 */
@Component
public class HotTierPruneJob {

    private static final Logger log = LoggerFactory.getLogger(HotTierPruneJob.class);

    private final ScanRecordRepository scans;
    private final long retentionDays;

    public HotTierPruneJob(ScanRecordRepository scans,
                           @Value("${cybershield.hot-retention-days:30}") long retentionDays) {
        this.scans = scans;
        this.retentionDays = retentionDays;
    }

    @Scheduled(cron = "${cybershield.prune-cron:0 30 3 * * *}")
    @Transactional
    public void prune() {
        Instant cutoff = Instant.now().minus(Duration.ofDays(retentionDays));
        long deleted = scans.deleteByCreatedAtBefore(cutoff);
        if (deleted > 0) {
            log.info("Hot-tier prune: removed {} scan records older than {} days", deleted, retentionDays);
        }
    }
}
