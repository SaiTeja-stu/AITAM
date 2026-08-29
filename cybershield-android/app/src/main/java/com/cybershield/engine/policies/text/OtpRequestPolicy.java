package com.cybershield.engine.policies.text;

import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;

import java.util.List;

/** MSG-02: message asks the recipient to share an OTP / PIN / CVV. Always critical. */
public class OtpRequestPolicy extends AbstractPolicy {

    public OtpRequestPolicy() {
        super("MSG-02", TEXT_LIKE);
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        String t = Keywords.lower(ctx.text().trim().isEmpty() ? ctx.rawContent() : ctx.text());
        if (t.trim().isEmpty()) return List.of();

        boolean mentionsOtp = Keywords.containsAny(t, Keywords.OTP);
        boolean asksToShare = t.contains("share") || t.contains("send me") || t.contains("tell me")
                || t.contains("provide") || t.contains("forward");

        if (mentionsOtp && asksToShare) {
            return one("Asks you to share a one-time code",
                    "Anyone who asks for your OTP, PIN or CVV is committing fraud. No bank, company or official ever needs it.",
                    Severity.CRITICAL, 50);
        }
        return List.of();
    }
}
