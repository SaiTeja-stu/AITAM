package com.cybershield.engine.policies.email;

import com.cybershield.domain.ContentType;
import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;
import com.cybershield.intel.LocalIntelStore;
import com.cybershield.mail.EmailMessage;

import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * EMAIL-01: the sender's <b>display name</b> claims a brand ("PayPal", "SBI"),
 * but the address it's actually from is not that brand's domain.
 *
 * <p>This is the single most common phishing tell — the human reads
 * "PayPal Service", the machine sees {@code no-reply@account-verify-secure.tk}.
 */
public class DisplayNameSpoofPolicy extends AbstractPolicy {

    private final LocalIntelStore intel;

    public DisplayNameSpoofPolicy(LocalIntelStore intel) {
        super("EMAIL-01", Set.of(ContentType.EMAIL));
        this.intel = intel;
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        var opt = ctx.email();
        if (opt.isEmpty()) return List.of();
        EmailMessage e = opt.get();
        String display = e.fromDisplayName().toLowerCase(Locale.ROOT);
        String domain = e.fromDomain();
        if (display.trim().isEmpty() || domain.trim().isEmpty()) return List.of();

        // if the sending domain is itself on the trusted allowlist, it's fine
        if (intel.isAllowedDomain(domain)) return List.of();

        String domainLabel = domain.contains(".") ? domain.substring(0, domain.indexOf('.')) : domain;

        for (String brand : intel.knownBrands()) {
            if (brand.length() < 4) continue;
            if (!display.contains(brand)) continue;
            if (domainLabel.equals(brand) || domain.contains(brand)) continue;   // domain also carries the brand -> not a mismatch here
            return one("Sender name impersonates " + brand,
                    "The email shows the sender as \"" + e.fromDisplayName() + "\" but it was actually sent from "
                            + e.fromAddress() + " (" + domain + "), which is not " + brand + "'s domain.",
                    Severity.HIGH, 32);
        }
        return List.of();
    }
}
