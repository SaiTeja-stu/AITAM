package com.cybershield.engine.policies.qr;

import com.cybershield.domain.ContentType;
import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;

import java.util.List;
import java.util.Set;

/** QR-07: the QR encodes a collect / mandate request (money pulled from the scanner). */
public class UpiCollectMandatePolicy extends AbstractPolicy {

    public UpiCollectMandatePolicy() {
        super("QR-07", Set.of(ContentType.QR));
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        var opt = ctx.upi();
        if (opt.isEmpty() || !opt.get().valid()) return List.of();
        if (opt.get().isCollectOrMandate()) {
            return one("Pull-payment / auto-debit request",
                    "This is a request to PULL money from your account (a collect or mandate request), not a payment you started. "
                            + "Decline unless you know exactly why you are being charged.",
                    Severity.CRITICAL, 45);
        }
        return List.of();
    }
}
