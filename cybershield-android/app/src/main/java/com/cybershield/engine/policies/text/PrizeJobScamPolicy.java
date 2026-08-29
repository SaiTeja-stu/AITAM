package com.cybershield.engine.policies.text;

import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;

import java.util.List;

/** MSG-05: lottery / prize / task-job advance-fee scam language. */
public class PrizeJobScamPolicy extends AbstractPolicy {

    public PrizeJobScamPolicy() {
        super("MSG-05", TEXT_LIKE);
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        String t = Keywords.lower(ctx.text().trim().isEmpty() ? ctx.rawContent() : ctx.text());
        if (t.trim().isEmpty()) return List.of();

        long hits = Keywords.countMatches(t, Keywords.PRIZE_JOB);
        boolean fee = t.contains("fee") || t.contains("deposit") || t.contains("charge")
                || t.contains("pay ") || t.contains("registration");
        if (hits >= 2 || (hits >= 1 && fee)) {
            return one("Prize / job advance-fee scam",
                    "The message promises easy money or a prize and will soon ask for an upfront 'fee' or 'deposit' you never get back.",
                    Severity.HIGH, 28);
        }
        return List.of();
    }
}
