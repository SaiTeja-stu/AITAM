package com.cybershield.engine.policies.email;

import com.cybershield.domain.ContentType;
import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;
import com.cybershield.intel.LocalIntelStore;
import com.cybershield.mail.EmailMessage;
import org.apache.commons.text.similarity.LevenshteinDistance;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * EMAIL-04: the sender's domain is a near-miss of a well-known brand
 * ({@code paypa1.com}, {@code sbi-secure.in}, {@code amaz0n-support.net}).
 */
@Component
public class SenderLookAlikePolicy extends AbstractPolicy {

    private final LocalIntelStore intel;
    private final LevenshteinDistance lev = new LevenshteinDistance(3);

    public SenderLookAlikePolicy(LocalIntelStore intel) {
        super("EMAIL-04", Set.of(ContentType.EMAIL));
        this.intel = intel;
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        var opt = ctx.email();
        if (opt.isEmpty()) return List.of();
        EmailMessage e = opt.get();
        String domain = e.fromDomain();
        if (domain.isBlank() || intel.isAllowedDomain(domain)) return List.of();

        String label = domain.contains(".") ? domain.substring(0, domain.indexOf('.')) : domain;
        String deLeet = label.replace('1', 'l').replace('0', 'o').replace('3', 'e')
                .replace('4', 'a').replace('5', 's').replace('$', 's');
        for (String brand : intel.knownBrands()) {
            if (brand.length() < 4 || label.equals(brand)) continue;
            Integer d = lev.apply(deLeet, brand);
            boolean near = d != null && d >= 0 && d <= 2 && Math.abs(deLeet.length() - brand.length()) <= 2;
            boolean brandAtStart = deLeet.equals(brand)
                    || deLeet.startsWith(brand + "-") || deLeet.startsWith(brand + ".");
            boolean shortContains = deLeet.contains(brand) && deLeet.length() <= brand.length() + 6;
            if (near || brandAtStart || shortContains) {
                return one("Sender domain imitates " + brand,
                        "This email came from " + e.fromAddress() + ". The domain '" + domain
                                + "' is a look-alike of " + brand + "'s real domain — not the same thing.",
                        Severity.HIGH, 30);
            }
        }
        return List.of();
    }
}
