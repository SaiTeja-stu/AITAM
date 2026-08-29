package com.cybershield.engine.policies.email;

import com.cybershield.domain.ContentType;
import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;
import com.cybershield.intel.DomainIntelService;
import com.cybershield.intel.LocalIntelStore;
import com.cybershield.mail.EmailMessage;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;

/**
 * EMAIL-05: how old is the sender's domain? (WHOIS/RDAP). Brands send from
 * domains registered years ago; a domain bought last week that is already
 * emailing you about your "account" is a strong phishing indicator.
 * Combined signal only — never decisive alone.
 */
@Component
public class SenderDomainAgePolicy extends AbstractPolicy {

    private final DomainIntelService domains;
    private final LocalIntelStore intel;

    public SenderDomainAgePolicy(DomainIntelService domains, LocalIntelStore intel) {
        super("EMAIL-05", Set.of(ContentType.EMAIL));
        this.domains = domains;
        this.intel = intel;
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        var opt = ctx.email();
        if (opt.isEmpty()) return List.of();
        EmailMessage e = opt.get();
        String domain = e.fromDomain();
        if (domain.isBlank() || intel.isAllowedDomain(domain)) return List.of();

        var infoOpt = domains.lookup(domain);
        if (infoOpt.isEmpty() || !infoOpt.get().hasAge()) return List.of();
        int age = infoOpt.get().ageDays();

        if (age <= 45) {
            return one("Sender's domain is brand-new",
                    "The domain " + domain + " was registered only " + age + " day" + (age == 1 ? "" : "s")
                            + " ago (WHOIS/RDAP). Real organisations email you from long-established domains.",
                    Severity.MEDIUM, 16);
        }
        return List.of();
    }
}
