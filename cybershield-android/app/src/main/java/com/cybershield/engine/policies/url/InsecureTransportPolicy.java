package com.cybershield.engine.policies.url;

import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;

import java.util.ArrayList;
import java.util.List;

/** URL-09: the link uses plain http:// (no transport encryption). */
public class InsecureTransportPolicy extends AbstractPolicy {

    public InsecureTransportPolicy() {
        super("URL-09", URL_LIKE);
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        List<Signal> out = new ArrayList<>();
        for (var u : ctx.allUrls()) {
            if (!u.isHttps() && !u.hostIsIpLiteral()) {
                out.add(signal("No HTTPS",
                        "'" + u.host() + "' is served over an unencrypted connection; data entered there can be intercepted.",
                        Severity.MEDIUM, 12));
            }
        }
        return out;
    }
}
