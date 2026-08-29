package com.cybershield.engine.policies.url;

import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;

import java.util.ArrayList;
import java.util.List;

/** URL-07: obfuscation tricks - credentials in URL, encoded chars, "@" redirect, excessive length. */
public class UrlObfuscationPolicy extends AbstractPolicy {

    public UrlObfuscationPolicy() {
        super("URL-07", URL_LIKE);
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        List<Signal> out = new ArrayList<>();
        for (var u : ctx.allUrls()) {
            String raw = u.original();
            if (u.hasUserInfo()) {
                out.add(signal("Credentials embedded in link",
                        "The URL contains a 'user@host' part, often used to make a malicious host look like a trusted one.",
                        Severity.HIGH, 24));
            }
            String afterScheme = raw.contains("://") ? raw.substring(raw.indexOf("://") + 3) : raw;
            if (afterScheme.contains("@")) {
                out.add(signal("Deceptive '@' in URL",
                        "Everything before '@' is ignored by browsers; the real destination is hidden after it.",
                        Severity.HIGH, 22));
            }
            if (raw.matches("(?i).*%(00|0a|0d|2f|5c|25).*")) {
                out.add(signal("Encoded control characters",
                        "The link contains percent-encoded characters that can disguise its true path.",
                        Severity.MEDIUM, 14));
            }
            if (raw.length() > 300) {
                out.add(signal("Unusually long URL",
                        "Very long links are frequently used to bury the real domain and confuse the reader.",
                        Severity.LOW, 6));
            }
        }
        return out;
    }
}
