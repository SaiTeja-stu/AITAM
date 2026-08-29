package com.cybershield.engine.policies.url;

import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;

import java.util.ArrayList;
import java.util.List;

/** URL-02: punycode / mixed-script host used for homograph attacks. */
public class PunycodeHomographPolicy extends AbstractPolicy {

    public PunycodeHomographPolicy() {
        super("URL-02", URL_LIKE);
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        List<Signal> out = new ArrayList<>();
        for (var u : ctx.allUrls()) {
            String host = u.host();
            if (host.contains("xn--")) {
                out.add(signal("Internationalised (punycode) domain",
                        "'" + host + "' uses punycode encoding, a common trick to spoof familiar names with look-alike letters.",
                        Severity.HIGH, 26));
            } else if (host.codePoints().anyMatch(c -> c > 127)) {
                out.add(signal("Non-ASCII characters in domain",
                        "The domain contains non-Latin characters that can visually mimic a legitimate site.",
                        Severity.HIGH, 24));
            }
        }
        return out;
    }
}
