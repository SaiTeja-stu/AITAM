package com.cybershield.engine.policies.url;

import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;
import com.cybershield.intel.LocalIntelStore;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/** URL-12 (TRUST): the primary domain is on the curated known-good allowlist. */
@Component
public class AllowlistUrlPolicy extends AbstractPolicy {

    private final LocalIntelStore intel;

    public AllowlistUrlPolicy(LocalIntelStore intel) {
        super("URL-12", URL_LIKE);
        this.intel = intel;
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        List<Signal> out = new ArrayList<>();
        ctx.primaryUrl().ifPresent(u -> {
            if (intel.isAllowedDomain(u.host())) {
                out.add(signal("Known trusted domain",
                        "'" + u.host() + "' is on the curated list of established, legitimate sites.",
                        Severity.TRUST, -30));
            }
        });
        return out;
    }
}
