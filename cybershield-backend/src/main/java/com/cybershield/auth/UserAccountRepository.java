package com.cybershield.auth;

import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface UserAccountRepository extends JpaRepository<UserAccount, String> {
    Optional<UserAccount> findByUsername(String username);
    Optional<UserAccount> findByEmail(String email);

    /** Accepts either the username or the email in one lookup (login by either). */
    default Optional<UserAccount> findByLogin(String login) {
        if (login == null) return Optional.empty();
        Optional<UserAccount> byUser = findByUsername(login);
        return byUser.isPresent() ? byUser : findByEmail(login.toLowerCase());
    }

    boolean existsByUsername(String username);
    boolean existsByEmail(String email);

    List<UserAccount> findByEmailVerifiedFalseAndCreatedAtBefore(Instant cutoff);
}
