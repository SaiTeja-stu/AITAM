package com.cybershield.web;

import com.cybershield.auth.AuthService;
import com.cybershield.web.dto.AuthDtos.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService auth;

    public AuthController(AuthService auth) {
        this.auth = auth;
    }

    private static final GenericMessage CHECK_EMAIL = new GenericMessage(
            "If the details are valid, we've sent a 6-digit code to that email address. " +
            "Enter it to activate your account.");

    private static final GenericMessage GENERIC_RESET = new GenericMessage(
            "If an account exists for that email, a reset code is on its way.");

    /** Create an account. Response is identical whether or not the email/username was free. */
    @PostMapping("/register")
    public ResponseEntity<GenericMessage> register(@Valid @RequestBody RegisterRequest req, HttpServletRequest http) {
        auth.register(req.email(), req.username(), req.password(), req.displayName(), ip(http));
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(CHECK_EMAIL);
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
        auth.resendVerification(req.email());
        return ResponseEntity.ok(CHECK_EMAIL);
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
        auth.forgotPassword(req.email(), ip(http));
        return ResponseEntity.ok(GENERIC_RESET);
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
