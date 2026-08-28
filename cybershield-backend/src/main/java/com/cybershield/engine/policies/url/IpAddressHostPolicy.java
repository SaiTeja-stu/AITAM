package com.cybershield.engine.policies.url;

import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/** URL-04: a raw IP address is used instead of a domain name. */
@Component
public class IpAddressHostPolicy extends AbstractPolicy {

    public IpAddressHostPolicy() {
        super("URL-04", URL_LIKE);
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        List<Signal> out = new ArrayList<>();
        for (var u : ctx.allUrls()) {
            if (u.hostIsIpLiteral()) {
                out.add(signal("IP address instead of a domain",
                        "The link points to a bare IP address (" + u.host() + "). Legitimate services almost always use a domain name.",
                        Severity.MEDIUM, 16));
            }
        }
        return out;
    }
}
