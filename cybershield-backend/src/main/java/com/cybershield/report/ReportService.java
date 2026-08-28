package com.cybershield.report;

import com.cybershield.common.Hashing;
import com.cybershield.common.PiiRedactor;
import com.cybershield.domain.ContentType;
import com.cybershield.intel.IndicatorType;
import com.cybershield.intel.LocalIntelStore;
import com.cybershield.qr.PayloadClassifier;
import com.cybershield.qr.PayloadKind;
import com.cybershield.qr.UpiUri;
import com.cybershield.url.UrlParts;
import org.springframework.stereotype.Service;

import java.util.UUID;

/** Stores user threat reports and extracts a matchable indicator from each. */
@Service
public class ReportService {

    private final ThreatReportRepository repo;
    private final PiiRedactor redactor;
    private final Hashing hashing;
    private final PayloadClassifier classifier;
    private final LocalIntelStore intel;

    public ReportService(ThreatReportRepository repo, PiiRedactor redactor, Hashing hashing,
                         PayloadClassifier classifier, LocalIntelStore intel) {
        this.repo = repo;
        this.redactor = redactor;
        this.hashing = hashing;
        this.classifier = classifier;
        this.intel = intel;
    }

    public String submit(ContentType type, String content, String note, String reporterId) {
        ThreatReport r = new ThreatReport();
        r.setId(UUID.randomUUID().toString());
        r.setType(type);
        r.setContentHash(hashing.sha256(type + "|" + content.trim().toLowerCase()));
        r.setSnippet(redactor.forLog(content));
        r.setReporterNote(note == null ? null : redactor.forLog(note));
        r.setReporterId(reporterId);
        r.setStatus(ThreatReport.Status.PENDING);
        extractIndicator(type, content, r);
        repo.save(r);
        return r.getId();
    }

    private void extractIndicator(ContentType type, String content, ThreatReport r) {
        if (type == ContentType.QR) {
            PayloadKind kind = classifier.classify(content);
            if (kind == PayloadKind.UPI_PAYMENT) {
                UpiUri upi = UpiUri.parse(content);
                upi.payeeVpa().ifPresent(vpa -> {
                    r.setIndicatorType(IndicatorType.VPA_HASH);
                    r.setIndicatorValue(hashing.hmac(vpa));
                });
                return;
            }
        }
        UrlParts.parse(type == ContentType.URL ? content : firstUrl(content))
                .ifPresent(u -> {
                    r.setIndicatorType(IndicatorType.DOMAIN);
                    r.setIndicatorValue(u.host());
                });
    }

    private String firstUrl(String text) {
        var m = java.util.regex.Pattern.compile("(?i)(https?://[^\\s\"'<>()]+)").matcher(text);
        return m.find() ? m.group(1) : "";
    }

    /** Admin: confirm a report so its indicator becomes an active blocklist entry. */
    public boolean confirm(String id) {
        return repo.findById(id).map(r -> {
            r.setStatus(ThreatReport.Status.CONFIRMED);
            repo.save(r);
            intel.refreshCommunity();
            return true;
        }).orElse(false);
    }

    /** Admin: reject a report (not a real threat / duplicate / noise). */
    public boolean reject(String id) {
        return repo.findById(id).map(r -> {
            r.setStatus(ThreatReport.Status.REJECTED);
            repo.save(r);
            intel.refreshCommunity();
            return true;
        }).orElse(false);
    }

    public org.springframework.data.domain.Page<ThreatReport> list(
            ThreatReport.Status status, org.springframework.data.domain.Pageable pageable) {
        return status == null
                ? repo.findAllByOrderByCreatedAtDesc(pageable)
                : repo.findByStatusOrderByCreatedAtDesc(status, pageable);
    }
}
