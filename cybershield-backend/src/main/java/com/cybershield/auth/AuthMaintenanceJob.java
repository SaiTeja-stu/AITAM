package com.cybershield.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Housekeeping:
 *  - delete never-verified accounts older than the grace window (a fake or
 *    mistyped email address results in an account that can never be used;
 *    this stops those piling up)
 *  - purge expired OTP challenges
 */
@Component
public class AuthMaintenanceJob {

    private static final Logger log = LoggerFactory.getLogger(AuthMaintenanceJob.class);
    private static final Logger securityLog = LoggerFactory.getLogger("SECURITY");

    private final UserAccountRepository users;
    private final OtpChallengeRepository otps;
    private final long unverifiedGraceHours;

    public AuthMaintenanceJob(UserAccountRepository users, OtpChallengeRepository otps,
                              @Value("${cybershield.auth.unverified-grace-hours:48}") long unverifiedGraceHours) {
        this.users = users;
        this.otps = otps;
        this.unverifiedGraceHours = unverifiedGraceHours;
    }

    @Scheduled(cron = "${cybershield.auth.cleanup-cron:0 15 * * * *}")
    @Transactional
    public void cleanup() {
        Instant cutoff = Instant.now().minus(Duration.ofHours(unverifiedGraceHours));
        List<UserAccount> stale = users.findByEmailVerifiedFalseAndCreatedAtBefore(cutoff);
        if (!stale.isEmpty()) {
            users.deleteAll(stale);
            securityLog.info("pruned {} unverified accounts older than {}h", stale.size(), unverifiedGraceHours);
        }
        int otpDeleted = otps.deleteExpired(Instant.now());
        if (otpDeleted > 0) {
            log.debug("purged {} expired OTP challenges", otpDeleted);
        }
    }
}
