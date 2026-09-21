package com.cybershield.engine.policies.text;

import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/** MSG-01 / EMAIL-06: urgency pressure, optionally combined with a credential request. */
public class UrgencyAndCredentialPolicy extends AbstractPolicy {

    /** "One Time Password" is a code name, not a request for your password. */
    private static final Pattern OTP_PHRASE = Pattern.compile("one[- ]time (?:password|pin|code)");
    /** "never share your OTP / password" is a safety warning, not a credential request. */
    private static final Pattern SAFETY_WARNING = Pattern.compile("\\b(?:do not|don't|dont|never|not to)\\s+(?:share|disclose|give|reveal|tell|provide|forward|send)\\b[^.!\\n]{0,60}");

    public UrgencyAndCredentialPolicy() {
        super("MSG-01", TEXT_LIKE);
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        String t = Keywords.lower(ctx.text().trim().isEmpty() ? ctx.rawContent() : ctx.text());
        if (t.trim().isEmpty()) return List.of();
        List<Signal> out = new ArrayList<>();
        String scan = OTP_PHRASE.matcher(SAFETY_WARNING.matcher(t).replaceAll(" ")).replaceAll("otp");

        boolean urgency = Keywords.containsAny(scan, Keywords.URGENCY);
        boolean creds = Keywords.containsAny(scan, Keywords.CREDENTIALS);
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
