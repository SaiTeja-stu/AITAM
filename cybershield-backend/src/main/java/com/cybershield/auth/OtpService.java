package com.cybershield.auth;

import com.cybershield.common.Hashing;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Issues and verifies 6-digit one-time codes for email verification and
 * password reset. Codes are single-use, time-limited, attempt-limited, and
 * stored only as HMACs.
 */
@Service
public class OtpService {

    private static final Logger securityLog = LoggerFactory.getLogger("SECURITY");
    private static final SecureRandom RNG = new SecureRandom();

    private final OtpChallengeRepository repo;
    private final Hashing hashing;
    private final Duration ttl;
    private final int maxAttempts;
    private final int maxPerHour;

    public OtpService(OtpChallengeRepository repo, Hashing hashing,
                      @Value("${cybershield.otp.ttl-minutes:15}") long ttlMinutes,
                      @Value("${cybershield.otp.max-attempts:5}") int maxAttempts,
                      @Value("${cybershield.otp.max-per-hour:5}") int maxPerHour) {
        this.repo = repo;
        this.hashing = hashing;
        this.ttl = Duration.ofMinutes(ttlMinutes);
        this.maxAttempts = maxAttempts;
        this.maxPerHour = maxPerHour;
    }

    public record Issued(String code, Instant expiresAt) {}

    /** Generate a fresh code, invalidating any previous unconsumed one for this purpose. */
    @Transactional
    public Optional<Issued> issue(String email, OtpChallenge.Purpose purpose) {
        String e = email.toLowerCase().trim();
        long recent = repo.countByEmailAndPurposeAndCreatedAtAfter(e, purpose, Instant.now().minus(Duration.ofHours(1)));
        if (recent >= maxPerHour) {
            securityLog.info("otp rate-limited email={} purpose={}", mask(e), purpose);
            return Optional.empty();
        }
        repo.consumeAll(e, purpose, Instant.now());

        String code = String.format("%06d", RNG.nextInt(1_000_000));
        OtpChallenge c = new OtpChallenge();
        c.setId(UUID.randomUUID().toString());
        c.setEmail(e);
        c.setPurpose(purpose);
        c.setCodeHash(hashing.hmac(purpose + ":" + code));
        c.setExpiresAt(Instant.now().plus(ttl));
        repo.save(c);
        securityLog.info("otp issued email={} purpose={} exp={}", mask(e), purpose, c.getExpiresAt());
        return Optional.of(new Issued(code, c.getExpiresAt()));
    }

    public enum Result { OK, INVALID, EXPIRED, TOO_MANY_ATTEMPTS, NOT_FOUND }

    /** Verify and consume a code. */
    @Transactional
    public Result verify(String email, OtpChallenge.Purpose purpose, String code) {
        String e = email.toLowerCase().trim();
        Optional<OtpChallenge> opt =
                repo.findFirstByEmailAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(e, purpose);
        if (opt.isEmpty()) return Result.NOT_FOUND;
        OtpChallenge c = opt.get();

        if (c.getExpiresAt().isBefore(Instant.now())) {
            securityLog.info("otp expired email={} purpose={}", mask(e), purpose);
            return Result.EXPIRED;
        }
        if (c.getAttempts() >= maxAttempts) {
            securityLog.info("otp too many attempts email={} purpose={}", mask(e), purpose);
            return Result.TOO_MANY_ATTEMPTS;
        }
        c.setAttempts(c.getAttempts() + 1);

        boolean match = hashing.hmac(purpose + ":" + (code == null ? "" : code.trim()))
                .equals(c.getCodeHash());
        if (!match) {
            repo.save(c);
            securityLog.info("otp mismatch email={} purpose={} attempt={}", mask(e), purpose, c.getAttempts());
            return Result.INVALID;
        }
        c.setConsumedAt(Instant.now());
        repo.save(c);
        securityLog.info("otp verified email={} purpose={}", mask(e), purpose);
        return Result.OK;
    }

    static String mask(String email) {
        if (email == null || !email.contains("@")) return "***";
        int at = email.indexOf('@');
        String local = email.substring(0, at);
        String shown = local.length() <= 2 ? local.charAt(0) + "*" : local.charAt(0) + "***" + local.charAt(local.length() - 1);
        return shown + email.substring(at);
    }
}
