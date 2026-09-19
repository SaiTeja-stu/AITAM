package com.cybershield.mail;

import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * All transactional email. Every send is async and fail-safe: a broken SMTP
 * connection is logged, never thrown, so it can't block sign-up or analysis.
 *
 * Configure via env: SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD,
 * MAIL_FROM. With no SMTP configured the service logs "would send ..." and
 * returns - the rest of the app still works.
 */
@Service
public class MailService {

    private static final Logger log = LoggerFactory.getLogger(MailService.class);
    private static final Logger securityLog = LoggerFactory.getLogger("SECURITY");
    private static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("dd MMM yyyy, HH:mm 'UTC'").withZone(ZoneId.of("UTC"));

    private final ObjectProvider<JavaMailSender> senderProvider;
    private final boolean enabled;
    private final String from;
    private final String appName;
    private final String brevoKey;

    private static final java.net.http.HttpClient HTTP = java.net.http.HttpClient.newBuilder()
            .connectTimeout(java.time.Duration.ofSeconds(8)).build();
    private static final com.fasterxml.jackson.databind.ObjectMapper MAPPER =
            new com.fasterxml.jackson.databind.ObjectMapper();

    public MailService(ObjectProvider<JavaMailSender> senderProvider,
                       @Value("${cybershield.mail.enabled:true}") boolean enabled,
                       @Value("${cybershield.mail.from:${SMTP_USERNAME:no-reply@cybershield.local}}") String from,
                       @Value("${cybershield.app-name:Secure Me}") String appName,
                       @Value("${BREVO_API_KEY:}") String brevoKey) {
        this.brevoKey = brevoKey == null ? "" : brevoKey.trim();
        this.senderProvider = senderProvider;
        this.enabled = enabled;
        this.from = from;
        this.appName = appName;
    }

    private void send(String to, String subject, String html) {
        if (!enabled || to == null || to.isBlank()) {
            log.info("mail disabled/skip: would send '{}' to {}", subject, mask(to));
            return;
        }
        if (!brevoKey.isEmpty()) {          // HTTPS email API: works where outbound SMTP ports are blocked
            sendViaBrevo(to, subject, html);
            return;
        }
        JavaMailSender sender = senderProvider.getIfAvailable();
        if (sender == null) {
            log.warn("no JavaMailSender configured: cannot send '{}' to {}", subject, mask(to));
            return;
        }
        try {
            MimeMessage msg = sender.createMimeMessage();
            MimeMessageHelper h = new MimeMessageHelper(msg, "UTF-8");
            h.setFrom(from);
            h.setTo(to);
            h.setSubject(subject);
            h.setText(EmailTemplates.wrap(appName, html), true);
            sender.send(msg);
            securityLog.info("mail sent subject='{}' to={}", subject, mask(to));
        } catch (Exception e) {
            log.warn("mail send failed ('{}' to {}): {}", subject, mask(to), e.toString());
        }
    }

    private void sendViaBrevo(String to, String subject, String html) {
        try {
            java.util.Map<String, Object> body = new java.util.LinkedHashMap<>();
            body.put("sender", java.util.Map.of("email", from, "name", appName));
            body.put("to", java.util.List.of(java.util.Map.of("email", to)));
            body.put("subject", subject);
            body.put("htmlContent", EmailTemplates.wrap(appName, html));
            java.net.http.HttpRequest req = java.net.http.HttpRequest
                    .newBuilder(java.net.URI.create("https://api.brevo.com/v3/smtp/email"))
                    .timeout(java.time.Duration.ofSeconds(15))
                    .header("api-key", brevoKey)
                    .header("content-type", "application/json")
                    .header("accept", "application/json")
                    .POST(java.net.http.HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(body)))
                    .build();
            java.net.http.HttpResponse<String> res = HTTP.send(req, java.net.http.HttpResponse.BodyHandlers.ofString());
            if (res.statusCode() / 100 == 2) {
                securityLog.info("mail sent (brevo) subject='{}' to={}", subject, mask(to));
            } else {
                String b = res.body() == null ? "" : res.body();
                log.warn("brevo send failed ('{}' to {}): HTTP {} {}", subject, mask(to), res.statusCode(),
                        b.substring(0, Math.min(200, b.length())));
            }
        } catch (Exception e) {
            log.warn("brevo send failed ('{}' to {}): {}", subject, mask(to), e.toString());
        }
    }

    @Async
    public void sendVerificationOtp(String to, String name, String code, Instant expiresAt) {
        send(to, appName + ": verify your email",
                EmailTemplates.verification(name, code, TS.format(expiresAt)));
    }

    @Async
    public void sendWelcome(String to, String name) {
        send(to, "Welcome to " + appName, EmailTemplates.welcome(name));
    }

    @Async
    public void sendSignInAlert(String to, String name, Instant when) {
        send(to, appName + ": new sign-in to your account",
                EmailTemplates.signInAlert(name, TS.format(when)));
    }

    @Async
    public void sendPasswordResetOtp(String to, String name, String code, String resetLink, Instant expiresAt) {
        send(to, appName + ": reset your password",
                EmailTemplates.passwordReset(name, code, resetLink, TS.format(expiresAt)));
    }

    @Async
    public void sendPasswordChanged(String to, String name, Instant when) {
        send(to, appName + ": your password was changed",
                EmailTemplates.passwordChanged(name, TS.format(when)));
    }

    @Async
    public void sendThreatAlert(String to, String name, String contentType, String riskLevel,
                                int score, String topSignal, String snippet) {
        send(to, appName + " blocked a " + riskLevel.replace('_', ' ').toLowerCase() + " threat",
                EmailTemplates.threatAlert(name, contentType, riskLevel, score, topSignal, snippet));
    }

    static String mask(String email) {
        if (email == null || !email.contains("@")) return "***";
        int at = email.indexOf('@');
        return email.charAt(0) + "***" + email.substring(at);
    }
}
