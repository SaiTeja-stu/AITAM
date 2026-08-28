package com.cybershield.auth;

import jakarta.persistence.*;

import java.time.Instant;

/** A dashboard / API user. Password is stored only as an Argon2/BCrypt hash. */
@Entity
@Table(name = "user_account")
public class UserAccount {

    @Id
    @Column(length = 36)
    private String id;

    @Column(nullable = false, unique = true, length = 64)
    private String username;

    @Column(unique = true, length = 190)
    private String email;

    @Column(length = 80)
    private String displayName;

    /** Encoded hash only - never plaintext, never logged, never serialised. */
    @Column(nullable = false, length = 120)
    private String passwordHash;

    @Column(nullable = false, length = 32)
    private String role = "ROLE_USER";

    @Column(nullable = false)
    private boolean enabled = true;

    /** Login is blocked until the user proves control of the email address. */
    @Column(nullable = false)
    private boolean emailVerified = false;

    @Column
    private Instant lastLoginAt;

    @Column(length = 64)
    private String lastLoginIp;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    public UserAccount() {}

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getDisplayName() { return displayName; }
    public void setDisplayName(String displayName) { this.displayName = displayName; }
    public String getPasswordHash() { return passwordHash; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }
    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public boolean isEmailVerified() { return emailVerified; }
    public void setEmailVerified(boolean emailVerified) { this.emailVerified = emailVerified; }
    public Instant getLastLoginAt() { return lastLoginAt; }
    public void setLastLoginAt(Instant lastLoginAt) { this.lastLoginAt = lastLoginAt; }
    public String getLastLoginIp() { return lastLoginIp; }
    public void setLastLoginIp(String lastLoginIp) { this.lastLoginIp = lastLoginIp; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
