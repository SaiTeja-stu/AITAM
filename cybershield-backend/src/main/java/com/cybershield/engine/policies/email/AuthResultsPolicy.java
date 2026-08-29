package com.cybershield.engine.policies.email;

import com.cybershield.domain.ContentType;
import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;
import com.cybershield.mail.EmailMessage;
import com.cybershield.mail.EmailMessage.Auth;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * EMAIL-02: read the receiving mail server's own SPF / DKIM / DMARC verdicts
 * from the {@code Authentication-Results} header — the exact checks Gmail runs.
 *
 * <ul>
 *   <li><b>SPF</b> — was this sending IP authorised by the From-domain's DNS?</li>
 *   <li><b>DKIM</b> — is the message cryptographically signed by the domain?</li>
 *   <li><b>DMARC</b> — does the visible From line pass, under the domain's policy?
 *       A DMARC <i>fail</i> means the domain owner is effectively saying
 *       "this did not come from us".</li>
 * </ul>
 */
@Component
public class AuthResultsPolicy extends AbstractPolicy {

    public AuthResultsPolicy() {
        super("EMAIL-02", Set.of(ContentType.EMAIL));
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        var opt = ctx.email();
        if (opt.isEmpty() || !opt.get().anyAuthChecked()) return List.of();
        EmailMessage e = opt.get();
        List<Signal> out = new ArrayList<>();

        if (e.dmarc() == Auth.FAIL) {
            out.add(signal("Failed DMARC authentication",
                    "The sender domain's published policy says this message is NOT genuine "
                            + "(DMARC failed). Legitimate mail from a real brand passes DMARC.",
                    Severity.HIGH, 30));
        } else if (e.authAllFailed()) {
            out.add(signal("Failed SPF and DKIM",
                    "Neither SPF (authorised sending server) nor DKIM (domain signature) passed — "
                            + "the sender is almost certainly forged.",
                    Severity.HIGH, 26));
        } else if (e.spf() == Auth.FAIL || e.dkim() == Auth.FAIL) {
            out.add(signal((e.spf() == Auth.FAIL ? "SPF" : "DKIM") + " check failed",
                    "One email-authentication check failed for this sender. Genuine bulk mail "
                            + "from a real organisation normally passes both.",
                    Severity.MEDIUM, 12));
        }
        return out;
    }
}
