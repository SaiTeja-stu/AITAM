package com.cybershield.auth;

import com.cybershield.mail.MailService;
import com.cybershield.security.JwtService;
import com.cybershield.security.LoginAttemptService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Registration, email verification, login, and password reset.
 *
 * Anti-enumeration: every "does this email/username exist" branch returns the
 * same generic response and burns comparable time (dummy hash). Login failures
 * are indistinguishable. Registration of a taken email/username looks identical
 * to success.
 *
 * A fake / mistyped email produces an account that can never be verified, so it
 * can never sign in; unverified accounts are pruned by {@link UnverifiedUserCleanupJob}.
 */
@Service
public class AuthService {

    private static final Logger securityLog = LoggerFactory.getLogger("SECURITY");
    private static final Pattern EMAIL_RE =
            Pattern.compile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");

    private final String dummyHash;

    private final UserAccountRepository users;
    private final OtpService otp;
    private final MailService mail;
    private final PasswordEncoder encoder;
    private final JwtService jwt;
    private final LoginAttemptService attempts;
    private final boolean requireEmailVerification;
    private final String resetBaseUrl;

    public AuthService(UserAccountRepository users, OtpService otp, MailService mail,
                       PasswordEncoder encoder, JwtService jwt, LoginAttemptService attempts,
                       @Value("${cybershield.auth.require-email-verification:true}") boolean requireEmailVerification,
                       @Value("${cybershield.auth.reset-url:}") String resetBaseUrl) {
        this.users = users;
        this.otp = otp;
        this.mail = mail;
        this.encoder = encoder;
        this.jwt = jwt;
        this.attempts = attempts;
        this.requireEmailVerification = requireEmailVerification;
        this.resetBaseUrl = resetBaseUrl;
        this.dummyHash = encoder.encode("timing-equalisation-placeholder-value");
    }

    // ---------------- registration ----------------

    /** Always looks the same to the caller, whether or not the details were free. */
    @Transactional
    public void register(String email, String username, String rawPassword, String displayName, String ip) {
        String e = normEmail(email);
        if (!EMAIL_RE.matcher(e).matches()) {
            // still return generic - but nothing is created / sent
            securityLog.info("register rejected (bad email format) ip={}", ip);
            return;
        }
        if (users.existsByEmail(e) || users.existsByUsername(username)) {
            securityLog.info("register attempt for existing email/username ip={}", ip);
            issueAndSendVerification(e, displayName); // resend so a real owner can still verify
            return;
        }
        UserAccount u = new UserAccount();
        u.setId(UUID.randomUUID().toString());
        u.setUsername(username);
        u.setEmail(e);
        u.setDisplayName(displayName == null || displayName.isBlank() ? username : displayName.trim());
        u.setPasswordHash(encoder.encode(rawPassword));
        u.setRole("ROLE_USER");
        u.setEmailVerified(!requireEmailVerification);
        users.save(u);
        securityLog.info("user registered id={} ip={} (verification required={})", u.getId(), ip, requireEmailVerification);

        if (requireEmailVerification) {
            issueAndSendVerification(e, u.getDisplayName());
        } else {
            mail.sendWelcome(e, u.getDisplayName());
        }
    }

    private void issueAndSendVerification(String email, String name) {
        otp.issue(email, OtpChallenge.Purpose.VERIFY_EMAIL).ifPresent(issued ->
                mail.sendVerificationOtp(email, name, issued.code(), issued.expiresAt()));
    }

    public enum SimpleResult { OK, INVALID, RATE_LIMITED, NOT_APPLICABLE }

    @Transactional
    public SimpleResult verifyEmail(String email, String code) {
        String e = normEmail(email);
        Optional<UserAccount> ou = users.findByEmail(e);
        OtpService.Result r = otp.verify(e, OtpChallenge.Purpose.VERIFY_EMAIL, code);
        if (r != OtpService.Result.OK) {
            return SimpleResult.INVALID;
        }
        if (ou.isPresent() && !ou.get().isEmailVerified()) {
            UserAccount u = ou.get();
            u.setEmailVerified(true);
            users.save(u);
            securityLog.info("email verified id={}", u.getId());
            mail.sendWelcome(e, u.getDisplayName());
        }
        return SimpleResult.OK;
    }

    public SimpleResult resendVerification(String email) {
        String e = normEmail(email);
        users.findByEmail(e).ifPresent(u -> {
            if (!u.isEmailVerified()) issueAndSendVerification(e, u.getDisplayName());
        });
        return SimpleResult.OK; // generic
    }

    // ---------------- login ----------------

    public sealed interface LoginResult
            permits LoginResult.Success, LoginResult.Failure, LoginResult.Locked, LoginResult.Unverified {
        record Success(String accessToken, long ttl) implements LoginResult {}
        record Failure() implements LoginResult {}
        record Locked() implements LoginResult {}
        record Unverified() implements LoginResult {}
    }

    @Transactional
    public LoginResult login(String login, String rawPassword, String clientIp) {
        String userKey = "u:" + (login == null ? "" : login.toLowerCase());
        String ipKey = "ip:" + clientIp;
        if (attempts.isBlocked(userKey) || attempts.isBlocked(ipKey)) {
            return new LoginResult.Locked();
        }

        Optional<UserAccount> found = users.findByLogin(login);
        boolean ok;
        if (found.isEmpty()) {
            encoder.matches(rawPassword, dummyHash);
            ok = false;
        } else {
            ok = found.get().isEnabled() && encoder.matches(rawPassword, found.get().getPasswordHash());
        }

        if (!ok) {
            attempts.onFailure(userKey);
            attempts.onFailure(ipKey);
            securityLog.info("failed login ip={}", clientIp);
            return new LoginResult.Failure();
        }

        UserAccount u = found.get();
        if (requireEmailVerification && !u.isEmailVerified()) {
            securityLog.info("login blocked - email unverified id={}", u.getId());
            issueAndSendVerification(u.getEmail(), u.getDisplayName());
            return new LoginResult.Unverified();
        }

        attempts.onSuccess(userKey);
        attempts.onSuccess(ipKey);
        u.setLastLoginAt(Instant.now());
        u.setLastLoginIp(clientIp);
        users.save(u);
        securityLog.info("login ok id={} ip={}", u.getId(), clientIp);

        if (u.getEmail() != null) {
            mail.sendSignInAlert(u.getEmail(), u.getDisplayName(), Instant.now());
        }
        String token = jwt.issue(u.getId(), u.getUsername(), u.getRole());
        return new LoginResult.Success(token, jwt.ttlSeconds());
    }

    // ---------------- password reset ----------------

    /** Generic response regardless of whether the email is registered. */
    public void forgotPassword(String email, String ip) {
        String e = normEmail(email);
        users.findByEmail(e).ifPresent(u ->
                otp.issue(e, OtpChallenge.Purpose.RESET_PASSWORD).ifPresent(issued -> {
                    String link = resetBaseUrl.isBlank() ? null
                            : resetBaseUrl + "?email=" + java.net.URLEncoder.encode(e, java.nio.charset.StandardCharsets.UTF_8)
                              + "&code=" + issued.code();
                    mail.sendPasswordResetOtp(e, u.getDisplayName(), issued.code(), link, issued.expiresAt());
                }));
        securityLog.info("password reset requested ip={}", ip);
    }

    @Transactional
    public SimpleResult resetPassword(String email, String code, String newPassword) {
        String e = normEmail(email);
        OtpService.Result r = otp.verify(e, OtpChallenge.Purpose.RESET_PASSWORD, code);
        if (r != OtpService.Result.OK) return SimpleResult.INVALID;

        Optional<UserAccount> ou = users.findByEmail(e);
        if (ou.isEmpty()) return SimpleResult.OK; // generic - don't reveal
        UserAccount u = ou.get();
        u.setPasswordHash(encoder.encode(newPassword));
        u.setEmailVerified(true); // proving control of the mailbox also verifies it
        users.save(u);
        securityLog.info("password reset completed id={}", u.getId());
        mail.sendPasswordChanged(e, u.getDisplayName(), Instant.now());
        return SimpleResult.OK;
    }

    private static String normEmail(String s) {
        return s == null ? "" : s.trim().toLowerCase(Locale.ROOT);
    }
}
