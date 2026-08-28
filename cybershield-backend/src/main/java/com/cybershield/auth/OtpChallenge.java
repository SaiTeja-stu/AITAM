package com.cybershield.auth;

import jakarta.persistence.*;

import java.time.Instant;

/**
 * A short-lived one-time code sent to an email address. Only the HMAC of the
 * code is stored, never the code itself.
 */
@Entity
@Table(name = "otp_challenge", indexes = {
        @Index(name = "ix_otp_email_purpose", columnList = "email,purpose"),
        @Index(name = "ix_otp_expires", columnList = "expiresAt")
})
public class OtpChallenge {

    public enum Purpose { VERIFY_EMAIL, RESET_PASSWORD }

    @Id
    @Column(length = 36)
    private String id;

    @Column(nullable = false, length = 190)
    private String email;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Purpose purpose;

    /** HMAC-SHA256 of the 6-digit code. */
    @Column(nullable = false, length = 80)
    private String codeHash;

    @Column(nullable = false)
    private int attempts = 0;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    @Column(nullable = false)
    private Instant expiresAt;

    @Column
    private Instant consumedAt;

    public OtpChallenge() {}

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public Purpose getPurpose() { return purpose; }
    public void setPurpose(Purpose purpose) { this.purpose = purpose; }
    public String getCodeHash() { return codeHash; }
    public void setCodeHash(String codeHash) { this.codeHash = codeHash; }
    public int getAttempts() { return attempts; }
    public void setAttempts(int attempts) { this.attempts = attempts; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
    public Instant getConsumedAt() { return consumedAt; }
    public void setConsumedAt(Instant consumedAt) { this.consumedAt = consumedAt; }
}
