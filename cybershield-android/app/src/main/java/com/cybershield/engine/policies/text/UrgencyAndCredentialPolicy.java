package com.cybershield.engine.policies.text;

import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;

import java.util.ArrayList;
import java.util.List;

/** MSG-01 / EMAIL-06: urgency pressure, optionally combined with a credential request. */
public class UrgencyAndCredentialPolicy extends AbstractPolicy {

    public UrgencyAndCredentialPolicy() {
        super("MSG-01", TEXT_LIKE);
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        String t = Keywords.lower(ctx.text().trim().isEmpty() ? ctx.rawContent() : ctx.text());
        if (t.trim().isEmpty()) return List.of();
        List<Signal> out = new ArrayList<>();

        boolean urgency = Keywords.containsAny(t, Keywords.URGENCY);
        boolean creds = Keywords.containsAny(t, Keywords.CREDENTIALS);
        boolean link = t.contains("http://") || t.contains("https://") || t.contains("click");

        if (urgency && (creds || link)) {
            out.add(signal("Urgency + action request",
                    "The message creates time pressure and pushes you to " +
                            (creds ? "hand over account details" : "click a link") +
                            " - a classic phishing structure.",
                    Severity.HIGH, 26));
        } else if (urgency) {
            out.add(signal("Pressure / urgency language",
                    "The message tries to rush you into acting before you can think it through.",
                    Severity.MEDIUM, 12));
        }
        if (creds) {
            out.add(signal("Requests confidential credentials",
                    "It asks for information (password, card number, KYC details) that a genuine organisation never requests this way.",
                    Severity.HIGH, 28));
        }
        return out;
    }
}
