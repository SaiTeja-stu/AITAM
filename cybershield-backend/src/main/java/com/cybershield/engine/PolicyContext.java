package com.cybershield.engine;

import com.cybershield.domain.ContentType;
import com.cybershield.qr.PayloadKind;
import com.cybershield.qr.UpiUri;
import com.cybershield.url.UrlParts;

import java.util.List;
import java.util.Optional;

/**
 * Normalized, pre-parsed view of the content under analysis. Built once by the
 * {@code AnalysisService} and passed to every {@link Policy}, so policies never
 * re-parse raw input.
 */
public final class PolicyContext {

    private final ContentType type;
    private final String rawContent;
    private final String text;                 // free text (email/sms/social body, or "")
    private final String html;                 // page HTML if fetched, or ""
    private final UrlParts primaryUrl;         // nullable
    private final List<UrlParts> embeddedUrls; // URLs found inside text/html
    private final PayloadKind qrKind;          // nullable (only for QR)
    private final UpiUri upi;                  // nullable
    private final String contentHash;

    private PolicyContext(Builder b) {
        this.type = b.type;
        this.rawContent = b.rawContent == null ? "" : b.rawContent;
        this.text = b.text == null ? "" : b.text;
        this.html = b.html == null ? "" : b.html;
        this.primaryUrl = b.primaryUrl;
        this.embeddedUrls = b.embeddedUrls == null ? List.of() : List.copyOf(b.embeddedUrls);
        this.qrKind = b.qrKind;
        this.upi = b.upi;
        this.contentHash = b.contentHash;
    }

    public ContentType type() { return type; }
    public String rawContent() { return rawContent; }
    public String text() { return text; }
    public String html() { return html; }
    public Optional<UrlParts> primaryUrl() { return Optional.ofNullable(primaryUrl); }
    public List<UrlParts> embeddedUrls() { return embeddedUrls; }
    public Optional<PayloadKind> qrKind() { return Optional.ofNullable(qrKind); }
    public Optional<UpiUri> upi() { return Optional.ofNullable(upi); }
    public String contentHash() { return contentHash; }

    /**
     * All URLs relevant to analysis: the primary plus any embedded, de-duplicated
     * by normalized form so a policy never counts the same link twice (which
     * would inflate the risk score).
     */
    public List<UrlParts> allUrls() {
        var seen = new java.util.LinkedHashMap<String, UrlParts>();
        if (primaryUrl != null) {
            seen.put(key(primaryUrl), primaryUrl);
        }
        for (UrlParts u : embeddedUrls) {
            seen.putIfAbsent(key(u), u);
        }
        return new java.util.ArrayList<>(seen.values());
    }

    private static String key(UrlParts u) {
        return u.scheme() + "://" + u.host() + (u.port() == -1 ? "" : ":" + u.port())
                + u.path() + "?" + u.query();
    }

    public static Builder builder(ContentType type) { return new Builder(type); }

    public static final class Builder {
        private final ContentType type;
        private String rawContent;
        private String text;
        private String html;
        private UrlParts primaryUrl;
        private List<UrlParts> embeddedUrls;
        private PayloadKind qrKind;
        private UpiUri upi;
        private String contentHash;

        private Builder(ContentType type) { this.type = type; }

        public Builder rawContent(String v) { this.rawContent = v; return this; }
        public Builder text(String v) { this.text = v; return this; }
        public Builder html(String v) { this.html = v; return this; }
        public Builder primaryUrl(UrlParts v) { this.primaryUrl = v; return this; }
        public Builder embeddedUrls(List<UrlParts> v) { this.embeddedUrls = v; return this; }
        public Builder qrKind(PayloadKind v) { this.qrKind = v; return this; }
        public Builder upi(UpiUri v) { this.upi = v; return this; }
        public Builder contentHash(String v) { this.contentHash = v; return this; }

        public PolicyContext build() { return new PolicyContext(this); }
    }
}
