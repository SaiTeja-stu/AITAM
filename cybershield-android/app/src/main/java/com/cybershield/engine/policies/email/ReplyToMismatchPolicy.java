package com.cybershield.engine.policies.email;

import com.cybershield.domain.ContentType;
import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;
import com.cybershield.mail.EmailMessage;

import java.util.List;
import java.util.Set;

/**
 * EMAIL-03: the visible sender is one domain, but replies are quietly routed to
 * a different one (or to a free webmail account). A common trick: spoof
 * {@code billing@company.com} in From, set {@code Reply-To: scammer123@gmail.com}
 * so the victim's reply goes straight to the attacker.
 */
public class ReplyToMismatchPolicy extends AbstractPolicy {

    private static final Set<String> FREEMAIL = Set.of(
            "gmail.com", "googlemail.com", "yahoo.com", "yahoo.in", "outlook.com",
            "hotmail.com", "live.com", "proton.me", "protonmail.com", "rediffmail.com",
            "aol.com", "mail.com", "yandex.com", "zoho.com");

    public ReplyToMismatchPolicy() {
        super("EMAIL-03", Set.of(ContentType.EMAIL));
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        var opt = ctx.email();
        if (opt.isEmpty()) return List.of();
        EmailMessage e = opt.get();
        String from = e.fromDomain();
        var replyOpt = e.replyToDomain();
        if (from.trim().isEmpty() || replyOpt.isEmpty()) return List.of();
        String reply = replyOpt.get();
        if (reply.equals(from) || reply.endsWith("." + from) || from.endsWith("." + reply)) return List.of();

        boolean replyIsFreemail = FREEMAIL.contains(reply);
        boolean fromLooksCorporate = !FREEMAIL.contains(from);

        if (replyIsFreemail && fromLooksCorporate) {
            return one("Replies go to a personal webmail account",
                    "The email appears to be from " + from + " but replies are directed to a free "
                            + reply + " address — a classic redirect used in invoice and CEO-fraud scams.",
                    Severity.HIGH, 24);
        }
        return one("Reply-To domain differs from the sender",
                "Replies to this message would go to " + reply + ", not " + from + ". "
                        + "Verify through a known channel before responding.",
                Severity.MEDIUM, 12);
    }
}
