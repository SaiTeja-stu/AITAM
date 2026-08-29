package com.cybershield.engine.policies.url;

import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;
import com.cybershield.intel.LocalIntelStore;

import java.util.ArrayList;
import java.util.List;

/** URL-08: the top-level domain is one heavily abused for abuse/malware. */
public class SuspiciousTldPolicy extends AbstractPolicy {

    private final LocalIntelStore intel;

    public SuspiciousTldPolicy(LocalIntelStore intel) {
        super("URL-08", URL_LIKE);
        this.intel = intel;
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        List<Signal> out = new ArrayList<>();
        for (var u : ctx.allUrls()) {
            if (intel.isAllowedDomain(u.host())) continue;
            if (intel.isSuspiciousTld(u.host())) {
                out.add(signal("High-abuse domain extension",
                        "The '." + u.host().substring(u.host().lastIndexOf('.') + 1)
                                + "' extension is disproportionately used for scams and malware.",
                        Severity.LOW, 7));
            }
        }
        return out;
    }
}
