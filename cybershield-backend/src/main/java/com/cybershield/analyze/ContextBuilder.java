package com.cybershield.analyze;

import com.cybershield.common.Hashing;
import com.cybershield.domain.ContentType;
import com.cybershield.engine.PolicyContext;
import com.cybershield.qr.PayloadClassifier;
import com.cybershield.qr.PayloadKind;
import com.cybershield.qr.UpiUri;
import com.cybershield.url.SafeFetchService;
import com.cybershield.url.UrlParts;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Turns a raw analyze request into a fully parsed {@link PolicyContext}:
 * classifies QR payloads, parses UPI URIs, extracts embedded URLs, and (for
 * WEBPAGE / URL) safely fetches page HTML via the SSRF-guarded fetcher.
 */
@Component
public class ContextBuilder {

    private static final Pattern URL_IN_TEXT = Pattern.compile(
            "(?i)\\b((?:https?://|www\\.)[^\\s\"'<>()]+)");

    private final PayloadClassifier classifier;
    private final SafeFetchService fetch;
    private final Hashing hashing;

    public ContextBuilder(PayloadClassifier classifier, SafeFetchService fetch, Hashing hashing) {
        this.classifier = classifier;
        this.fetch = fetch;
        this.hashing = hashing;
    }

    public record Built(PolicyContext context, boolean hadNetworkData, UpiUri upi, PayloadKind qrKind) {}

    public Built build(ContentType type, String content, String pageUrl) {
        String raw = content == null ? "" : content.trim();
        var builder = PolicyContext.builder(type)
                .rawContent(raw)
                .contentHash(hashing.sha256(type + "|" + raw.toLowerCase()));

        boolean network = false;
        UpiUri upi = null;
        PayloadKind qrKind = null;

        switch (type) {
            case URL, WEBPAGE -> {
                String target = (type == ContentType.WEBPAGE && pageUrl != null && !pageUrl.isBlank())
                        ? pageUrl : raw;
                UrlParts.parse(target).ifPresent(builder::primaryUrl);
                if (type == ContentType.WEBPAGE && !raw.isBlank() && raw.length() > 40 && raw.contains("<")) {
                    builder.html(raw); // caller supplied the HTML directly
                } else {
                    var fetched = fetch.fetch(target);
                    if (fetched.isPresent()) {
                        builder.html(fetched.get().body());
                        UrlParts.parse(fetched.get().finalUrl()).ifPresent(builder::primaryUrl);
                    }
                }
                network = true;
            }
            case QR -> {
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
            }
            case EMAIL, SMS, SOCIAL -> builder.text(raw);
        }

        List<UrlParts> embedded = extractUrls(raw);
        if (!embedded.isEmpty()) {
            builder.embeddedUrls(embedded);
        }

        return new Built(builder.build(), network, upi, qrKind);
    }

    private List<UrlParts> extractUrls(String text) {
        List<UrlParts> out = new ArrayList<>();
        if (text == null || text.isBlank()) return out;
        Matcher m = URL_IN_TEXT.matcher(text);
        int count = 0;
        while (m.find() && count < 10) {
            UrlParts.parse(m.group(1)).ifPresent(out::add);
            count++;
        }
        return out;
    }
}
