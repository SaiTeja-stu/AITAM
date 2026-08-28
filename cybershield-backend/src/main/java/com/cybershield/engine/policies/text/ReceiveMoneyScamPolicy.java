package com.cybershield.engine.policies.text;

import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * MSG-03: "scan / approve this to RECEIVE money". In UPI, scanning a QR or
 * approving a request only ever debits you. Any such claim is a scam.
 */
@Component
public class ReceiveMoneyScamPolicy extends AbstractPolicy {

    public ReceiveMoneyScamPolicy() {
        super("MSG-03", TEXT_LIKE);
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        String t = Keywords.lower(ctx.text().isBlank() ? ctx.rawContent() : ctx.text());
        if (t.isBlank()) return List.of();

        if (Keywords.containsAny(t, Keywords.UPI_RECEIVE)) {
            return one("\"Scan to receive money\" claim",
                    "Scanning a QR or approving a UPI request NEVER credits your account - it only sends money out. "
                            + "This message is a scam.",
                    Severity.CRITICAL, 52);
        }
        return List.of();
    }
}
