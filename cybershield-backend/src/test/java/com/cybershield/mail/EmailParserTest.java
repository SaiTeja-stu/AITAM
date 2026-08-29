package com.cybershield.mail;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class EmailParserTest {

    private static String load(String name) throws IOException {
        try (var in = EmailParserTest.class.getResourceAsStream("/emails/" + name)) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Test
    void parses_genuine_headers() throws Exception {
        EmailMessage e = EmailParser.parse(load("genuine_amazon.eml"));
        assertThat(e.hadHeaders()).isTrue();
        assertThat(e.fromDisplayName()).isEqualTo("Amazon.in");
        assertThat(e.fromAddress()).isEqualTo("shipment-tracking@amazon.in");
        assertThat(e.fromDomain()).isEqualTo("amazon.in");
        assertThat(e.spf()).isEqualTo(EmailMessage.Auth.PASS);
        assertThat(e.dkim()).isEqualTo(EmailMessage.Auth.PASS);
        assertThat(e.dmarc()).isEqualTo(EmailMessage.Auth.PASS);
        assertThat(e.links()).anyMatch(l -> l.contains("amazon.in"));
    }

    @Test
    void parses_phishing_headers() throws Exception {
        EmailMessage e = EmailParser.parse(load("phishing_paypal.eml"));
        assertThat(e.fromDisplayName()).isEqualTo("PayPal Service");
        assertThat(e.fromDomain()).isEqualTo("paypa1-account-verify.tk");
        assertThat(e.replyToDomain()).contains("gmail.com");
        assertThat(e.spf()).isEqualTo(EmailMessage.Auth.FAIL);
        assertThat(e.dkim()).isEqualTo(EmailMessage.Auth.FAIL);
        assertThat(e.dmarc()).isEqualTo(EmailMessage.Auth.FAIL);
        assertThat(e.firstReceivedIp()).isEqualTo("45.133.1.9");
        assertThat(e.links()).anyMatch(l -> l.contains("paypa1-account-verify.tk"));
    }

    @Test
    void bare_body_without_headers() {
        EmailMessage e = EmailParser.parse("Hi, click http://evil.tk/login to verify your account now.");
        assertThat(e.hadHeaders()).isFalse();
        assertThat(e.anyAuthChecked()).isFalse();
        assertThat(e.links()).containsExactly("http://evil.tk/login");
    }

    @Test
    void domain_extraction_handles_cctld() {
        assertThat(EmailParser.domainOf("a@mail.sbi.co.in")).isEqualTo("sbi.co.in");
        assertThat(EmailParser.domainOf("x@paypal.com")).isEqualTo("paypal.com");
    }
}
