package com.cybershield.engine.policies.text;

import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;

import java.util.List;

/** MSG-10: "digital arrest" / police-impersonation extortion script (high prevalence in India). */
public class DigitalArrestPolicy extends AbstractPolicy {

    public DigitalArrestPolicy() {
        super("MSG-10", TEXT_LIKE);
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        String t = Keywords.lower(ctx.text().trim().isEmpty() ? ctx.rawContent() : ctx.text());
        if (t.trim().isEmpty()) return List.of();

        long hits = Keywords.countMatches(t, Keywords.DIGITAL_ARREST);
        if (hits >= 1) {
            return one("\"Digital arrest\" / police-impersonation scam",
                    "Law enforcement never arrests, interrogates or fines people over a call or chat. Do not pay, do not stay on the line.",
                    Severity.CRITICAL, 50);
        }
        return List.of();
    }
}
