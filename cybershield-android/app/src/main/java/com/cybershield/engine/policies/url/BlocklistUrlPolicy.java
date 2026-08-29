package com.cybershield.engine.policies.url;

import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;
import com.cybershield.intel.LocalIntelStore;

import java.util.ArrayList;
import java.util.List;

/** URL-10: the domain is on the shipped threat blocklist or confirmed community reports. */
public class BlocklistUrlPolicy extends AbstractPolicy {

    private final LocalIntelStore intel;

    public BlocklistUrlPolicy(LocalIntelStore intel) {
        super("URL-10", URL_LIKE);
        this.intel = intel;
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        List<Signal> out = new ArrayList<>();
        for (var u : ctx.allUrls()) {
            if (intel.isBlockedDomain(u.host())) {
                out.add(signal("Known malicious site",
                        "The domain '" + u.host() + "' appears on a threat blocklist or has been reported by users.",
                        Severity.CRITICAL, 55));
            }
        }
        return out;
    }
}
