package com.cybershield.mail;

import java.util.List;
import java.util.Optional;

/**
 * A parsed email, reduced to the fields that matter for phishing analysis.
 *
 * <p>{@code spf} / {@code dkim} / {@code dmarc} are the results the RECEIVING mail
 * server already computed and stamped into the {@code Authentication-Results}
 * header — the same checks Gmail runs before deciding "spam". We don't
 * re-validate cryptographically; we read the receiver's verdict.
 */
public record EmailMessage(
        String fromDisplayName,   // "PayPal Service"   (may be "")
        String fromAddress,       // "service@paypal.com" lowercased (may be "")
        String fromDomain,        // "paypal.com"        registrable domain of fromAddress
        String replyToAddress,    // may be ""
        String returnPathDomain,  // envelope sender domain, may be ""
        String subject,
        Auth spf,
        Auth dkim,
        Auth dmarc,
        String firstReceivedIp,   // originating IP from the earliest Received: hop, may be ""
        String body,              // text (HTML stripped)
        List<String> links,
        boolean hadHeaders        // false when the input was just a pasted body
) {
    public enum Auth { PASS, FAIL, NONE, UNKNOWN }

    public Optional<String> replyToDomain() {
        int at = replyToAddress == null ? -1 : replyToAddress.indexOf('@');
        return at < 0 ? Optional.empty()
                : Optional.of(replyToAddress.substring(at + 1).toLowerCase());
    }

    public boolean authAllFailed() {
        return spf == Auth.FAIL && dkim == Auth.FAIL;
    }

    public boolean anyAuthChecked() {
        return spf != Auth.UNKNOWN || dkim != Auth.UNKNOWN || dmarc != Auth.UNKNOWN;
    }
}
