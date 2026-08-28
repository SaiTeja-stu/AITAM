package com.cybershield.engine.policies.behavioral;

import com.cybershield.common.Hashing;
import com.cybershield.domain.ContentType;
import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;
import com.cybershield.report.ThreatReportRepository;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;

/** X-01/X-02: this exact content has been reported before (matched by content hash). */
@Component
public class CommunityReportPolicy extends AbstractPolicy {

    private final ThreatReportRepository reports;
    private final Hashing hashing;

    public CommunityReportPolicy(ThreatReportRepository reports, Hashing hashing) {
        super("X-01", Set.of(ContentType.values()));
        this.reports = reports;
        this.hashing = hashing;
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        String hash = ctx.contentHash();
        if (hash == null || hash.isBlank()) return List.of();
        long count = reports.countByContentHash(hash);
        if (count >= 3) {
            return one("Reported by multiple users",
                    count + " people have reported this exact content as a scam.",
                    Severity.CRITICAL, 45);
        } else if (count >= 1) {
            return one("Previously reported",
                    "This content has been reported as suspicious before.",
                    Severity.MEDIUM, 18);
        }
        return List.of();
    }
}
