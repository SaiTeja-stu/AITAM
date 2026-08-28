package com.cybershield.web.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** Authentication request/response payloads. */
public final class AuthDtos {
    private AuthDtos() {}

    public record RegisterRequest(
            @NotBlank @Email @Size(max = 190)
            String email,

            @NotBlank @Size(min = 3, max = 64)
            @Pattern(regexp = "^[a-zA-Z0-9_.-]+$", message = "username: letters, digits, _ . - only")
            String username,

            @Size(max = 80)
            String displayName,

            @NotBlank @Size(min = 12, max = 128, message = "password must be at least 12 characters")
            String password
    ) {}

    /** Login by username OR email. */
    public record LoginRequest(
            @NotBlank @Size(max = 190) String login,
            @NotBlank @Size(max = 128) String password
    ) {}

    public record VerifyEmailRequest(
            @NotBlank @Email String email,
            @NotBlank @Pattern(regexp = "\\d{6}", message = "code must be 6 digits") String code
    ) {}

    public record EmailOnlyRequest(
            @NotBlank @Email String email
    ) {}

    public record ResetPasswordRequest(
            @NotBlank @Email String email,
            @NotBlank @Pattern(regexp = "\\d{6}", message = "code must be 6 digits") String code,
            @NotBlank @Size(min = 12, max = 128, message = "password must be at least 12 characters") String newPassword
    ) {}

    public record TokenResponse(String accessToken, String tokenType, long expiresInSeconds) {}

    /** Deliberately generic - never reveals whether the account existed. */
    public record GenericMessage(String message) {}
}
