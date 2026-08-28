package com.cybershield.qr;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** QR payload classification + UPI parsing (spec: decode -> validate -> classify -> extract). */
class QrPipelineTest {

    private final PayloadClassifier classifier = new PayloadClassifier();

    @Test
    void classifies_upi_url_and_text() {
        assertThat(classifier.classify("upi://pay?pa=x@ybl&am=10")).isEqualTo(PayloadKind.UPI_PAYMENT);
        assertThat(classifier.classify("https://example.com/a")).isEqualTo(PayloadKind.URL);
        assertThat(classifier.classify("example.com/promo")).isEqualTo(PayloadKind.URL);
        assertThat(classifier.classify("WIFI:S:net;T:WPA;P:pw;;")).isEqualTo(PayloadKind.WIFI);
        assertThat(classifier.classify("just some words")).isEqualTo(PayloadKind.PLAIN_TEXT);
    }

    @Test
    void parses_upi_pay_uri() {
        UpiUri u = UpiUri.parse("upi://pay?pa=merchant@ybl&pn=Corner%20Store&am=499.50&cu=INR&tn=order123");
        assertThat(u.valid()).isTrue();
        assertThat(u.payeeVpa()).contains("merchant@ybl");
        assertThat(u.payeeName()).contains("Corner Store");
        assertThat(u.amount()).contains(499.50);
        assertThat(u.currency()).contains("INR");
        assertThat(u.isCollectOrMandate()).isFalse();
        assertThat(u.initiatesDebit()).isTrue();
    }

    @Test
    void detects_collect_and_mandate_as_pull_payments() {
        assertThat(UpiUri.parse("upi://collect?pa=x@ybl&am=5000").isCollectOrMandate()).isTrue();
        assertThat(UpiUri.parse("upi://mandate?pa=x@ybl&am=999").isCollectOrMandate()).isTrue();
    }

    @Test
    void malformed_upi_is_not_valid_and_does_not_throw() {
        UpiUri u = UpiUri.parse("upi://pay?%%%&=&am=abc");
        assertThat(u.valid()).isFalse();
        assertThat(u.amount()).isEmpty();
    }

    @Test
    void non_upi_string_yields_invalid() {
        assertThat(UpiUri.parse("https://not-upi.example").valid()).isFalse();
        assertThat(UpiUri.parse(null).valid()).isFalse();
    }
}
