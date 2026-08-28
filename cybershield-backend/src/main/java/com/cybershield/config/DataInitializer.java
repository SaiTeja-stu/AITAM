package com.cybershield.config;

import com.cybershield.auth.UserAccount;
import com.cybershield.auth.UserAccountRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * Bootstraps a single, pre-verified admin account on first run from env vars
 * CYBERSHIELD_ADMIN_USER / CYBERSHIELD_ADMIN_PASSWORD (+ optional
 * CYBERSHIELD_ADMIN_EMAIL). Skipped if the user already exists. Never logs the
 * password.
 */
@Component
public class DataInitializer implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

    private final UserAccountRepository users;
    private final PasswordEncoder encoder;
    private final String adminUser;
    private final String adminPassword;
    private final String adminEmail;

    public DataInitializer(UserAccountRepository users, PasswordEncoder encoder,
                           @Value("${cybershield.admin.username:}") String adminUser,
                           @Value("${cybershield.admin.password:}") String adminPassword,
                           @Value("${cybershield.admin.email:}") String adminEmail) {
        this.users = users;
        this.encoder = encoder;
        this.adminUser = adminUser;
        this.adminPassword = adminPassword;
        this.adminEmail = adminEmail;
    }

    @Override
    public void run(String... args) {
        if (adminUser.isBlank() || adminPassword.isBlank()) {
            log.info("No admin bootstrap configured (set cybershield.admin.username/password to create one).");
            return;
        }
        if (users.existsByUsername(adminUser)) {
            return;
        }
        UserAccount u = new UserAccount();
        u.setId(UUID.randomUUID().toString());
        u.setUsername(adminUser);
        u.setEmail(adminEmail.isBlank() ? null : adminEmail.trim().toLowerCase());
        u.setDisplayName("Administrator");
        u.setPasswordHash(encoder.encode(adminPassword));
        u.setRole("ROLE_ADMIN");
        u.setEmailVerified(true);   // bootstrap account is trusted
        users.save(u);
        log.info("Bootstrapped admin account '{}'", adminUser);
    }
}
