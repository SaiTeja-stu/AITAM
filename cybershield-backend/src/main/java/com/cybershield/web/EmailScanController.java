package com.cybershield.web;

import com.cybershield.analyze.AnalysisService;
import com.cybershield.domain.ContentType;
import com.cybershield.mail.EmailMessage;
import com.cybershield.mail.EmailParser;
import com.cybershield.web.dto.AnalyzeResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Spec-shaped email scanner ({@code POST /api/analyze-email}).
 *
 * <p>Accepts a raw email — ideally the full source from Gmail's "Show original"
 * or a {@code .eml} — and runs it through the same pipeline as
 * {@code type=EMAIL}: header authentication (SPF/DKIM/DMARC), sender-domain and
 * display-name checks, link analysis, and the text/social-engineering policies.
 */
@RestController
@RequestMapping("/api")
public class EmailScanController {

    private final AnalysisService analysis;

    public EmailScanController(AnalysisService analysis) {
        this.analysis = analysis;
    }

    public record EmailRequest(
            @NotBlank(message = "raw email text is required")
            @Size(max = 200_000, message = "email too large")
            String raw) {}

    @PostMapping("/analyze-email")
    public Map<String, Object> analyzeEmail(@Valid @RequestBody EmailRequest req,
                                            @RequestHeader(value = "X-Client", required = false) String client) {
        EmailMessage parsed = EmailParser.parse(req.raw());
        AnalyzeResponse v = analysis.analyze(ContentType.EMAIL, req.raw(), null, client, CurrentUser.id(), true);
        return shape(parsed, v);
    }

    private Map<String, Object> shape(EmailMessage e, AnalyzeResponse v) {
        List<Map<String, Object>> indicators = new ArrayList<>();
        for (AnalyzeResponse.SignalDto s : v.signals()) {
            if (s.weight() <= 0) continue;
            Map<String, Object> ind = new LinkedHashMap<>();
            ind.put("type", indicatorType(s.policyId()));
            ind.put("severity", s.severity());
            ind.put("message", s.detail());
            ind.put("policy_id", s.policyId());
            indicators.add(ind);
        }

        Map<String, Object> sender = new LinkedHashMap<>();
        sender.put("display_name", e.fromDisplayName());
        sender.put("address", e.fromAddress());
        sender.put("domain", e.fromDomain());
        sender.put("reply_to", e.replyToAddress());
        sender.put("subject", e.subject());
        sender.put("headers_present", e.hadHeaders());

        Map<String, Object> auth = new LinkedHashMap<>();
        auth.put("spf", e.spf().name());
        auth.put("dkim", e.dkim().name());
        auth.put("dmarc", e.dmarc().name());
        auth.put("checked", e.anyAuthChecked());
        auth.put("note", e.anyAuthChecked() ? null
                : "No Authentication-Results header — paste the full source from Gmail's \"Show original\" for SPF/DKIM/DMARC.");

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("verdict", e.hadHeaders() || v.riskScore() > 0 ? spamVerdict(v.riskScore()) : "UNKNOWN");
        out.put("risk_score", v.riskScore());
        out.put("risk_level", UrlScanController.fiveLevel(v.riskScore()));
        out.put("confidence", Math.round(v.confidence()) / 100.0);
        out.put("sender", sender);
        out.put("authentication", auth);
        out.put("links", e.links());
        out.put("indicators", indicators);
        out.put("explanation", v.explanation());
        out.put("recommendations", v.recommendations());
        out.put("report_id", v.reportId());
        out.put("analyzed_at", v.analyzedAt());
        return out;
    }

    /** Gmail-style bucket. */
    private static String spamVerdict(int score) {
        if (score >= 60) return "PHISHING";
        if (score >= 35) return "LIKELY_SPAM";
        if (score >= 15) return "SUSPICIOUS";
        return "LOOKS_LEGITIMATE";
    }

    private static String indicatorType(String policyId) {
        return switch (policyId) {
            case "EMAIL-01" -> "DISPLAY_NAME_SPOOF";
            case "EMAIL-02" -> "FAILED_EMAIL_AUTH";
            case "EMAIL-03" -> "REPLY_TO_MISMATCH";
            case "EMAIL-04" -> "LOOKALIKE_SENDER_DOMAIN";
            case "EMAIL-05" -> "NEW_SENDER_DOMAIN";
            case "MSG-01" -> "URGENCY_PRESSURE";
            case "MSG-02" -> "CREDENTIAL_OR_OTP_REQUEST";
            case "MSG-05" -> "ADVANCE_FEE_SCAM";
            case "MSG-06" -> "BRAND_IMPERSONATION";
            case "URL-01", "URL-05" -> "PHISHING_LINK";
            case "URL-10" -> "MALICIOUS_LINK";
            case "URL-13" -> "ML_URL_RISK";
            default -> policyId.startsWith("URL") ? "SUSPICIOUS_LINK"
                    : policyId.startsWith("MSG") ? "SOCIAL_ENGINEERING" : "OTHER";
        };
    }
}
