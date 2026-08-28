package com.cybershield.analyze;

import com.cybershield.auth.UserAccountRepository;
import com.cybershield.domain.RiskLevel;
import com.cybershield.domain.Signal;
import com.cybershield.domain.Verdict;
import com.cybershield.mail.MailService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Emails a logged-in user when their scan comes back HIGH_RISK or MALICIOUS.
 * Rate-limited per user so a burst of scans can't flood their inbox.
 */
@Service
public class ThreatNotifier {

    private static final Logger log = LoggerFactory.getLogger(ThreatNotifier.class);

    private final UserAccountRepository users;
    private final MailService mail;
    private final boolean enabled;
    private final Duration minGap;
    private final Map<String, Instant> lastSent = new ConcurrentHashMap<>();

    public ThreatNotifier(UserAccountRepository users, MailService mail,
                          @Value("${cybershield.mail.threat-alerts:true}") boolean enabled,
                          @Value("${cybershield.mail.threat-alert-min-gap-minutes:10}") long minGapMinutes) {
        this.users = users;
        this.mail = mail;
        this.enabled = enabled;
        this.minGap = Duration.ofMinutes(minGapMinutes);
    }

    public void maybeNotify(String ownerId, String contentType, Verdict v, String redactedSnippet) {
        if (!enabled || ownerId == null) return;
        if (v.getRiskLevel() != RiskLevel.MALICIOUS && v.getRiskLevel() != RiskLevel.HIGH_RISK) return;

        Instant prev = lastSent.get(ownerId);
        if (prev != null && Duration.between(prev, Instant.now()).compareTo(minGap) < 0) return;

        users.findById(ownerId).ifPresent(u -> {
            if (u.getEmail() == null || !u.isEmailVerified()) return;
            lastSent.put(ownerId, Instant.now());
            String topSignal = v.getSignals().stream()
                    .filter(s -> s.weight() > 0)
                    .findFirst()
                    .map(Signal::name)
                    .orElse("multiple warning signs");
            try {
                mail.sendThreatAlert(u.getEmail(), u.getDisplayName(), contentType,
                        v.getRiskLevel().name(), v.getRiskScore(), topSignal, redactedSnippet);
            } catch (RuntimeException e) {
                log.debug("threat alert send skipped: {}", e.toString());
            }
        });
    }
}
