package com.cybershield.engine.policies.url;

import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;
import com.cybershield.intel.DomainIntelService;
import com.cybershield.intel.LocalIntelStore;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * DNS-01: how old is the domain? Freshly-registered domains are heavily
 * over-represented in phishing (a scam domain is used within days of purchase).
 *
 * <p>Data source: RDAP / WHOIS via {@link DomainIntelService}. This is a risk
 * <i>indicator</i> only — a new domain is never proof of fraud on its own, so
 * the weight is modest and capped at MEDIUM. Allowlisted domains are skipped.
 */
@Component
public class DomainAgePolicy extends AbstractPolicy {

    private final DomainIntelService domains;
    private final LocalIntelStore intel;

    public DomainAgePolicy(DomainIntelService domains, LocalIntelStore intel) {
        super("DNS-01", URL_LIKE);
        this.domains = domains;
        this.intel = intel;
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        var urlOpt = ctx.primaryUrl();
        if (urlOpt.isEmpty()) return List.of();
        String host = urlOpt.get().host();
        if (intel.isAllowedDomain(host)) return List.of();

        var infoOpt = domains.lookup(host);
        if (infoOpt.isEmpty() || !infoOpt.get().hasAge()) return List.of();

        int age = infoOpt.get().ageDays();
        List<Signal> out = new ArrayList<>();
        if (age <= 30) {
            out.add(signal("Very new domain",
                    "This domain was registered only " + age + " day" + (age == 1 ? "" : "s")
                            + " ago (source: WHOIS/RDAP). Scam sites are usually used within days of registration.",
                    Severity.MEDIUM, 16));
        } else if (age <= 120) {
            out.add(signal("Recently registered domain",
                    "This domain is about " + (age / 30) + " month" + (age / 30 == 1 ? "" : "s")
                            + " old (source: WHOIS/RDAP) — treat unexpected requests from it with caution.",
                    Severity.LOW, 6));
        }
        return out;
    }
}
