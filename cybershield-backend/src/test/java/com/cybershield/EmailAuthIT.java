package com.cybershield;

import com.cybershield.mail.MailService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.TestPropertySource;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Full email-verification + password-reset flow. Mail is captured via a mock
 * so the test can read the OTP that would have been emailed.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "cybershield.auth.require-email-verification=true",
        "cybershield.mail.enabled=true"
})
class EmailAuthIT {

    @LocalServerPort int port;
    @MockBean MailService mail;

    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper mapper = new ObjectMapper();
    private String base;

    @BeforeEach
    void setUp() {
        base = "http://localhost:" + port;
        reset(mail);
    }

    private HttpResponse<String> post(String path, String body) {
        try {
            return http.send(HttpRequest.newBuilder(URI.create(base + path))
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(10))
                    .POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                    HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String captureVerificationCode(String email) {
        ArgumentCaptor<String> code = ArgumentCaptor.forClass(String.class);
        verify(mail, timeout(2000).atLeastOnce()).sendVerificationOtp(eq(email), any(), code.capture(), any());
        var all = code.getAllValues();
        return all.get(all.size() - 1); // most recent code is the valid one
    }

    @Test
    void register_then_verify_then_login() throws Exception {
        String email = "flowuser@example.com";
        var reg = post("/auth/register",
                "{\"email\":\"" + email + "\",\"username\":\"flowuser\",\"password\":\"averylongpassword12\"}");
        assertThat(reg.statusCode()).isEqualTo(202);

        // login is blocked before verification
        var early = post("/auth/login", "{\"login\":\"flowuser\",\"password\":\"averylongpassword12\"}");
        assertThat(early.statusCode()).isEqualTo(403);

        String otp = captureVerificationCode(email);
        var verify = post("/auth/verify-email", "{\"email\":\"" + email + "\",\"code\":\"" + otp + "\"}");
        assertThat(verify.statusCode()).isEqualTo(200);

        var ok = post("/auth/login", "{\"login\":\"flowuser\",\"password\":\"averylongpassword12\"}");
        assertThat(ok.statusCode()).isEqualTo(200);
        assertThat(mapper.readTree(ok.body()).has("accessToken")).isTrue();

        // welcome + sign-in alert were sent
        verify(mail, timeout(2000)).sendWelcome(eq(email), any());
        verify(mail, timeout(2000)).sendSignInAlert(eq(email), any(), any(Instant.class));
    }

    @Test
    void wrong_otp_is_rejected() {
        String email = "badotp@example.com";
        post("/auth/register",
                "{\"email\":\"" + email + "\",\"username\":\"badotp\",\"password\":\"averylongpassword12\"}");
        captureVerificationCode(email);
        var r = post("/auth/verify-email", "{\"email\":\"" + email + "\",\"code\":\"000000\"}");
        assertThat(r.statusCode()).isEqualTo(400);
    }

    @Test
    void forgot_password_flow_resets_and_allows_login() {
        String email = "resetme@example.com";
        post("/auth/register",
                "{\"email\":\"" + email + "\",\"username\":\"resetme\",\"password\":\"averylongpassword12\"}");
        String verifyCode = captureVerificationCode(email);
        post("/auth/verify-email", "{\"email\":\"" + email + "\",\"code\":\"" + verifyCode + "\"}");
        reset(mail);

        var forgot = post("/auth/forgot-password", "{\"email\":\"" + email + "\"}");
        assertThat(forgot.statusCode()).isEqualTo(200);

        ArgumentCaptor<String> code = ArgumentCaptor.forClass(String.class);
        verify(mail, timeout(2000)).sendPasswordResetOtp(eq(email), any(), code.capture(), any(), any());

        var doReset = post("/auth/reset-password",
                "{\"email\":\"" + email + "\",\"code\":\"" + code.getValue() + "\",\"newPassword\":\"brandnewpassword99\"}");
        assertThat(doReset.statusCode()).isEqualTo(200);
        verify(mail, timeout(2000)).sendPasswordChanged(eq(email), any(), any(Instant.class)); // unchanged

        var login = post("/auth/login", "{\"login\":\"resetme\",\"password\":\"brandnewpassword99\"}");
        assertThat(login.statusCode()).isEqualTo(200);
    }

    @Test
    void forgot_password_for_unknown_email_is_still_generic_200() {
        var r = post("/auth/forgot-password", "{\"email\":\"nobody-here@example.com\"}");
        assertThat(r.statusCode()).isEqualTo(200);
        verify(mail, never()).sendPasswordResetOtp(any(), any(), any(), any(), any());
    }
}
