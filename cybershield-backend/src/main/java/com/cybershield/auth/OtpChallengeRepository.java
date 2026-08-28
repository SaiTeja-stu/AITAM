package com.cybershield.auth;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;

public interface OtpChallengeRepository extends JpaRepository<OtpChallenge, String> {

    Optional<OtpChallenge> findFirstByEmailAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
            String email, OtpChallenge.Purpose purpose);

    long countByEmailAndPurposeAndCreatedAtAfter(String email, OtpChallenge.Purpose purpose, Instant since);

    @Modifying
    @Query("delete from OtpChallenge o where o.expiresAt < :cutoff")
    int deleteExpired(@Param("cutoff") Instant cutoff);

    @Modifying
    @Query("update OtpChallenge o set o.consumedAt = :now where o.email = :email and o.purpose = :purpose and o.consumedAt is null")
    void consumeAll(@Param("email") String email, @Param("purpose") OtpChallenge.Purpose purpose, @Param("now") Instant now);
}
