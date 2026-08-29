package com.cybershield.engine.policies.url;

import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;
import com.cybershield.intel.LocalIntelStore;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** URL-05: a brand name appears in the subdomain of an unrelated registered domain. */
public class DeceptiveSubdomainPolicy extends AbstractPolicy {

    private final LocalIntelStore intel;

    public DeceptiveSubdomainPolicy(LocalIntelStore intel) {
        super("URL-05", URL_LIKE);
        this.intel = intel;
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        List<Signal> out = new ArrayList<>();
        for (var u : ctx.allUrls()) {
            String host = u.host().toLowerCase(Locale.ROOT);
            String base = u.baseDomain().toLowerCase(Locale.ROOT);
            if (host.equals(base)) continue;
            String sub = host.substring(0, host.length() - base.length());
            if (intel.isAllowedDomain(host)) continue;
            for (String brand : intel.knownBrands()) {
                if (sub.contains(brand) && !base.contains(brand)) {
                    out.add(signal("Brand name in subdomain",
                            "'" + brand + "' appears in the subdomain but the site is actually registered as '" + base + "'.",
                            Severity.HIGH, 28));
                    break;
                }
            }
            long dots = host.chars().filter(c -> c == '.').count();
            if (dots >= 4) {
                out.add(signal("Excessive subdomains",
                        "The host has an unusually deep subdomain chain, often used to look legitimate at a glance.",
                        Severity.LOW, 6));
            }
        }
        return out;
    }
}
