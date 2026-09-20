package com.cybershield.web;

import com.cybershield.auth.AuthService;
import com.cybershield.auth.UserAccount;
import com.cybershield.auth.UserAccountRepository;
import com.cybershield.web.dto.AuthDtos.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService auth;
    private final UserAccountRepository users;

    public AuthController(AuthService auth, UserAccountRepository users) {
        this.auth = auth;
        this.users = users;
    }

    /** Who am I, and which extra consoles (admin / investigator) does my role unlock. */
    @GetMapping("/me")
    public ResponseEntity<?> me() {
        String id = CurrentUser.id();
        if (id == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        return users.findById(id)
                .<ResponseEntity<?>>map(u -> ResponseEntity.ok(Map.of(
                        "id", u.getId(),
                        "username", u.getUsername(),
                        "email", u.getEmail() == null ? "" : u.getEmail(),
                        "admin", "ROLE_ADMIN".equals(u.getRole()),
                        "investigator", "ROLE_INVESTIGATOR".equals(u.getRole())
                )))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).build());
    }

    private static ResponseEntity<GenericMessage> msg(HttpStatus status, String text) {
        return ResponseEntity.status(status).body(new GenericMessage(text));
    }

    /** Create an account. Tells the user plainly if the email or username is already taken. */
    @PostMapping("/register")
    public ResponseEntity<GenericMessage> register(@Valid @RequestBody RegisterRequest req, HttpServletRequest http) {
        return switch (auth.register(req.email(), req.username(), req.password(), req.displayName(), ip(http))) {
            case CREATED -> msg(HttpStatus.ACCEPTED, auth.requiresEmailVerification()
                    ? "Account created. We emailed a 6-digit code to " + req.email().trim() + ". Enter it to finish."
                    : "Account created. You can sign in now.");
            case RESENT -> msg(HttpStatus.ACCEPTED,
                    "You had already started signing up with this email. We sent you a new 6-digit code.");
            case EMAIL_TAKEN -> msg(HttpStatus.CONFLICT,
                    "An account with this email already exists. Sign in, or use \"Forgot password\".");
            case USERNAME_TAKEN -> msg(HttpStatus.CONFLICT,
                    "That username is already taken. Please choose a different one.");
            case BAD_EMAIL -> msg(HttpStatus.BAD_REQUEST, "Enter a valid email address.");
        };
    }

    @PostMapping("/verify-email")
    public ResponseEntity<GenericMessage> verify(@Valid @RequestBody VerifyEmailRequest req) {
        var r = auth.verifyEmail(req.email(), req.code());
        return r == AuthService.SimpleResult.OK
                ? ResponseEntity.ok(new GenericMessage("Email verified. You can now sign in."))
                : ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new GenericMessage("That code is invalid or has expired."));
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<GenericMessage> resend(@Valid @RequestBody EmailOnlyRequest req) {
        return switch (auth.resendVerification(req.email())) {
            case SENT -> msg(HttpStatus.OK, "A new 6-digit code is on its way to " + req.email().trim() + ".");
            case NO_ACCOUNT -> msg(HttpStatus.NOT_FOUND, "No account found for that email. Create an account first.");
            case ALREADY_VERIFIED -> msg(HttpStatus.OK, "This email is already verified. You can sign in.");
            case RATE_LIMITED -> msg(HttpStatus.TOO_MANY_REQUESTS,
                    "Too many codes requested. Please wait a while before asking for another.");
        };
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest req, HttpServletRequest http) {
        return switch (auth.login(req.login(), req.password(), ip(http))) {
            case AuthService.LoginResult.Success s ->
                    ResponseEntity.ok(new TokenResponse(s.accessToken(), "Bearer", s.ttl()));
            case AuthService.LoginResult.Locked l ->
                    ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                            .body(new GenericMessage("Too many attempts. Try again later."));
            case AuthService.LoginResult.Unverified u ->
                    ResponseEntity.status(HttpStatus.FORBIDDEN)
                            .body(new GenericMessage("Verify your email first. We've sent you a new code."));
            case AuthService.LoginResult.Failure f ->
                    ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(new GenericMessage("Invalid credentials."));
        };
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<GenericMessage> forgot(@Valid @RequestBody EmailOnlyRequest req, HttpServletRequest http) {
        return switch (auth.forgotPassword(req.email(), ip(http))) {
            case SENT -> msg(HttpStatus.OK,
                    "We sent a 6-digit code to " + req.email().trim() + ". It is valid for 15 minutes.");
            case NO_ACCOUNT -> msg(HttpStatus.NOT_FOUND,
                    "No account found for that email. Check the address, or create an account.");
            case RATE_LIMITED -> msg(HttpStatus.TOO_MANY_REQUESTS,
                    "Too many codes requested. Please wait a while and try again.");
        };
    }

    @PostMapping("/reset-password")
    public ResponseEntity<GenericMessage> reset(@Valid @RequestBody ResetPasswordRequest req) {
        var r = auth.resetPassword(req.email(), req.code(), req.newPassword());
        return r == AuthService.SimpleResult.OK
                ? ResponseEntity.ok(new GenericMessage("Password updated. You can sign in with your new password."))
                : ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new GenericMessage("That code is invalid or has expired."));
    }

    private String ip(HttpServletRequest req) {
        String xff = req.getHeader("X-Forwarded-For");
        return (xff != null && !xff.isBlank()) ? xff.split(",")[0].trim() : req.getRemoteAddr();
    }
}
