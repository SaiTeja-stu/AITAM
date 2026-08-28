package com.cybershield.analyze;

import com.cybershield.common.PiiRedactor;
import com.cybershield.domain.*;
import com.cybershield.engine.DetectionEngine;
import com.cybershield.engine.RiskScorer;
import com.cybershield.intel.LocalIntelStore;
import com.cybershield.qr.UpiUri;
import com.cybershield.scan.ScanRecord;
import com.cybershield.scan.ScanRecordRepository;
import com.cybershield.storage.ColdLogWriter;
import com.cybershield.web.dto.AnalyzeResponse;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Orchestrates the full analysis pipeline and persists both storage tiers. */
@Service
public class AnalysisService {

    private final ContextBuilder contextBuilder;
    private final DetectionEngine engine;
    private final RiskScorer scorer;
    private final ExplanationService explanations;
    private final LlmExplanationService llm;
    private final LocalIntelStore intel;
    private final PiiRedactor redactor;
    private final ScanRecordRepository scanRepo;
    private final ColdLogWriter coldLog;
    private final ThreatNotifier threatNotifier;

    public AnalysisService(ContextBuilder contextBuilder, DetectionEngine engine, RiskScorer scorer,
                           ExplanationService explanations, LlmExplanationService llm,
                           LocalIntelStore intel, PiiRedactor redactor,
                           ScanRecordRepository scanRepo, ColdLogWriter coldLog,
                           ThreatNotifier threatNotifier) {
        this.contextBuilder = contextBuilder;
        this.engine = engine;
        this.scorer = scorer;
        this.explanations = explanations;
        this.llm = llm;
        this.intel = intel;
        this.redactor = redactor;
        this.scanRepo = scanRepo;
        this.coldLog = coldLog;
        this.threatNotifier = threatNotifier;
    }

    public AnalyzeResponse analyze(ContentType type, String content, String pageUrl,
                                   String source, String ownerId, boolean persist) {

        ContextBuilder.Built built = contextBuilder.build(type, content, pageUrl);
        List<Signal> signals = engine.run(built.context());

        Verdict v = new Verdict();
        signals.forEach(v::addSignal);
        int score = scorer.score(signals);
        v.setRiskScore(score);
        v.setRiskLevel(scorer.level(score));
        v.setConfidence(scorer.confidence(signals, built.hadNetworkData()));

        // Trust wording: only when on the curated allowlist AND nothing negative fired.
        built.context().primaryUrl().ifPresent(u -> {
            if (intel.isAllowedDomain(u.host()) && signals.stream().noneMatch(s -> s.weight() > 0)) {
                v.setTrusted(true);
            }
        });
        // "verified" stays false: no authoritative verification source wired in yet.

        UpiUri upi = built.upi();
        boolean initiatesPayment = upi != null && upi.initiatesDebit();
        explanations.enrich(v, type, upi, initiatesPayment);

        String reportId = UUID.randomUUID().toString();
        String snippet = redactor.forLog(content);

        // Optional: rewrite the explanation with the LLM (no-op unless ANTHROPIC_API_KEY set).
        llm.maybeRewrite(v, type, snippet);

        if (persist) {
            persistHot(reportId, type, built.context().contentHash(), snippet, v, ownerId);
            coldLog.write(reportId, type.name(), built.context().contentHash(), snippet, v, source, ownerId);
            threatNotifier.maybeNotify(ownerId, type.name(), v, snippet);
        }

        return toResponse(reportId, type, v, upi, initiatesPayment);
    }

    private void persistHot(String id, ContentType type, String hash, String snippet, Verdict v, String ownerId) {
        try {
            ScanRecord r = new ScanRecord();
            r.setId(id);
            r.setType(type);
            r.setContentHash(hash);
            r.setSnippet(snippet);
            r.setRiskScore(v.getRiskScore());
            r.setRiskLevel(v.getRiskLevel());
            r.setPriority(v.getRiskLevel().priority());
            r.setConfidence(v.getConfidence());
            r.setVerified(v.isVerified());
            r.setOwnerId(ownerId);
            r.setCreatedAt(Instant.now());
            scanRepo.save(r);
        } catch (RuntimeException ignored) {
            // hot-tier persistence is best-effort; the cold log is the source of truth
        }
    }

    private AnalyzeResponse toResponse(String id, ContentType type, Verdict v, UpiUri upi, boolean initiatesPayment) {
        List<AnalyzeResponse.SignalDto> sigs = v.getSignals().stream()
                .map(s -> new AnalyzeResponse.SignalDto(
                        s.policyId(), s.name(), s.detail(), s.severity().name(), s.weight()))
                .toList();

        AnalyzeResponse.PaymentInfo payment = null;
        if (upi != null && upi.valid()) {
            payment = new AnalyzeResponse.PaymentInfo(
                    "UPI",
                    upi.action(),
                    upi.payeeVpa().orElse(null),
                    upi.payeeName().orElse(null),
                    upi.amount().orElse(null),
                    upi.currency().orElse("INR"),
                    upi.note().orElse(null),
                    upi.isCollectOrMandate());
        }

        return new AnalyzeResponse(
                id,
                type.name(),
                v.getRiskScore(),
                v.getRiskLevel().name(),
                v.getRiskLevel().priority(),
                v.wording(),
                v.getConfidence(),
                v.isVerified(),
                v.isTrusted(),
                initiatesPayment,
                v.getCategories(),
                sigs,
                v.getExplanation(),
                v.getRecommendations(),
                payment,
                Instant.now());
    }
}
