package com.cybershield.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;

/**
 * Issues and validates short-lived HS256 access tokens.
 * Secret comes from configuration/env (never hard-coded in a real deployment).
 * Validation enforces signature, expiry, issuer and audience, and rejects
 * "alg: none" implicitly (jjwt refuses unsigned tokens on a MAC key).
 */
@Service
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);
    private static final String ISSUER = "cybershield";
    private static final String AUDIENCE = "cybershield-clients";

    private final SecretKey key;
    private final long ttlSeconds;

    public JwtService(
            @Value("${cybershield.jwt.secret:}") String secret,
            @Value("${cybershield.jwt.ttl-seconds:900}") long ttlSeconds) {
        if (secret == null || secret.getBytes(StandardCharsets.UTF_8).length < 32) {
            // Dev fallback: generate an ephemeral key so the app still boots.
            log.warn("cybershield.jwt.secret missing/short - using an ephemeral key (tokens won't survive restart)");
            this.key = Jwts.SIG.HS256.key().build();
        } else {
            this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        }
        this.ttlSeconds = ttlSeconds;
    }

    public long ttlSeconds() { return ttlSeconds; }

    public String issue(String subjectUserId, String username, String role) {
        Instant now = Instant.now();
        return Jwts.builder()
                .issuer(ISSUER)
                .audience().add(AUDIENCE).and()
                .subject(subjectUserId)
                .claim("username", username)
                .claim("role", role)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(ttlSeconds)))
                .signWith(key)
                .compact();
    }

    public Optional<AuthenticatedUser> validate(String token) {
        try {
            Claims c = Jwts.parser()
                    .verifyWith(key)
                    .requireIssuer(ISSUER)
                    .requireAudience(AUDIENCE)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return Optional.of(new AuthenticatedUser(
                    c.getSubject(),
                    c.get("username", String.class),
                    c.get("role", String.class)));
        } catch (Exception e) {
            log.debug("JWT rejected: {}", e.getClass().getSimpleName());
            return Optional.empty();
        }
    }

    public record AuthenticatedUser(String userId, String username, String role) {}
}
