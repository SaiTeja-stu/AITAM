package com.cybershield.analyze;

import com.cybershield.domain.ContentType;
import com.cybershield.engine.PolicyContext;
import com.cybershield.qr.PayloadClassifier;
import com.cybershield.qr.PayloadKind;
import com.cybershield.qr.UpiUri;
import com.cybershield.url.UrlParts;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Turns a raw analyze request into a fully parsed {@link PolicyContext}.
 *
 * <p>On-device variant of the backend builder: it does NOT fetch remote pages
 * (no server, and fetching arbitrary URLs from the phone is an SSRF/-privacy
 * risk). WEBPAGE analysis therefore only uses HTML the caller already has
 * (e.g. supplied by the browser extension).
 */
public final class ContextBuilder {

    private static final Pattern URL_IN_TEXT = Pattern.compile(
            "(?i)\\b((?:https?://|www\\.)[^\\s\"'<>()]+)");

    private final PayloadClassifier classifier = new PayloadClassifier();

    public static final class Built {
        private final PolicyContext context;
        private final boolean hadNetworkData;
        private final UpiUri upi;
        private final PayloadKind qrKind;

        Built(PolicyContext context, boolean hadNetworkData, UpiUri upi, PayloadKind qrKind) {
            this.context = context;
            this.hadNetworkData = hadNetworkData;
            this.upi = upi;
            this.qrKind = qrKind;
        }

        public PolicyContext context() { return context; }
        public boolean hadNetworkData() { return hadNetworkData; }
        public UpiUri upi() { return upi; }
        public PayloadKind qrKind() { return qrKind; }
    }

    public Built build(ContentType type, String content, String pageUrl) {
        String raw = content == null ? "" : content.trim();
        var builder = PolicyContext.builder(type)
                .rawContent(raw)
                .contentHash(sha256(type + "|" + raw.toLowerCase()));

        UpiUri upi = null;
        PayloadKind qrKind = null;
        com.cybershield.mail.EmailMessage email = null;

        switch (type) {
            case URL:
            case WEBPAGE: {
                String target = (type == ContentType.WEBPAGE && pageUrl != null && !pageUrl.trim().isEmpty())
                        ? pageUrl : raw;
                UrlParts.parse(target).ifPresent(builder::primaryUrl);
                if (type == ContentType.WEBPAGE && raw.length() > 40 && raw.contains("<")) {
                    builder.html(raw); // caller supplied the HTML directly
                }
                break;
            }
            case QR: {
                qrKind = classifier.classify(raw);
                builder.qrKind(qrKind);
                if (qrKind == PayloadKind.UPI_PAYMENT) {
                    upi = UpiUri.parse(raw);
                    builder.upi(upi);
                } else if (qrKind == PayloadKind.URL) {
                    UrlParts.parse(raw).ifPresent(builder::primaryUrl);
                } else {
                    builder.text(raw);
                }
                break;
            }
            case EMAIL: {
                email = com.cybershield.mail.EmailParser.parse(raw);
                builder.email(email);
                builder.text(email.hadHeaders() ? email.body() : raw);
                break;
            }
            case SMS:
            case SOCIAL:
                builder.text(raw);
                break;
        }

        String forUrlScan = raw;
        if (email != null) {
            StringBuilder sb = new StringBuilder(email.body()).append('\n');
            for (String l : email.links()) sb.append(l).append('\n');
            forUrlScan = sb.toString();
        }
        List<UrlParts> embedded = extractUrls(forUrlScan);
        if (!embedded.isEmpty()) {
            builder.embeddedUrls(embedded);
        }

        return new Built(builder.build(), false, upi, qrKind);
    }

    private List<UrlParts> extractUrls(String text) {
        List<UrlParts> out = new ArrayList<>();
        if (text == null || text.trim().isEmpty()) return out;
        Matcher m = URL_IN_TEXT.matcher(text);
        int count = 0;
        while (m.find() && count < 10) {
            UrlParts.parse(m.group(1)).ifPresent(out::add);
            count++;
        }
        return out;
    }

    private static String sha256(String value) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] out = md.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(out.length * 2);
            for (byte b : out) sb.append(Character.forDigit((b >> 4) & 0xF, 16))
                                 .append(Character.forDigit(b & 0xF, 16));
            return sb.toString();
        } catch (Exception e) {
            return Integer.toHexString(value.hashCode());
        }
    }
}
