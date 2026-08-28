package com.cybershield.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Limits login attempts. Two independent counters:
 *  - per username  : locks after {@code maxAttempts} failures (fast, targeted)
 *  - per client IP : locks after {@code maxAttempts * ipFactor} failures
 *                    (guards against spraying many usernames from one host)
 * After the threshold the key is locked for {@code lockMinutes}.
 * In-memory; swap for Redis for multi-node.
 */
@Service
public class LoginAttemptService {

    private final int maxAttempts;
    private final int ipFactor;
    private final Duration window;
    private final Duration lockout;

    private final Map<String, Attempt> attempts = new ConcurrentHashMap<>();

    public LoginAttemptService(
            @Value("${cybershield.auth.max-attempts:5}") int maxAttempts,
            @Value("${cybershield.auth.ip-factor:20}") int ipFactor,
            @Value("${cybershield.auth.window-minutes:15}") long windowMinutes,
            @Value("${cybershield.auth.lock-minutes:15}") long lockMinutes) {
        this.maxAttempts = maxAttempts;
        this.ipFactor = Math.max(1, ipFactor);
        this.window = Duration.ofMinutes(windowMinutes);
        this.lockout = Duration.ofMinutes(lockMinutes);
    }

    private static final class Attempt {
        int count;
        Instant firstAt = Instant.now();
        Instant lockedUntil;
    }

    public boolean isBlocked(String key) {
        Attempt a = attempts.get(norm(key));
        return a != null && a.lockedUntil != null && a.lockedUntil.isAfter(Instant.now());
    }

    public void onFailure(String key) {
        String k = norm(key);
        int threshold = k.startsWith("ip:") ? maxAttempts * ipFactor : maxAttempts;
        attempts.compute(k, (kk, a) -> {
            Instant now = Instant.now();
            if (a == null || Duration.between(a.firstAt, now).compareTo(window) > 0) {
                a = new Attempt();
            }
            a.count++;
            if (a.count >= threshold) {
                a.lockedUntil = now.plus(lockout);
            }
            return a;
        });
    }

    public void onSuccess(String key) {
        attempts.remove(norm(key));
    }

    /** Test / ops hook. */
    public void reset() {
        attempts.clear();
    }

    private String norm(String key) {
        return key == null ? "" : key.trim().toLowerCase();
    }
}
