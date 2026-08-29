package com.cybershield.core;

import android.content.Context;

import com.cybershield.analyze.ContextBuilder;
import com.cybershield.analyze.ExplanationService;
import com.cybershield.domain.ContentType;
import com.cybershield.domain.RiskLevel;
import com.cybershield.domain.Signal;
import com.cybershield.domain.Verdict;
import com.cybershield.engine.DetectionEngine;
import com.cybershield.engine.Policy;
import com.cybershield.engine.RiskScorer;
import com.cybershield.engine.policies.email.AuthResultsPolicy;
import com.cybershield.engine.policies.email.DisplayNameSpoofPolicy;
import com.cybershield.engine.policies.email.ReplyToMismatchPolicy;
import com.cybershield.engine.policies.email.SenderLookAlikePolicy;
import com.cybershield.engine.policies.qr.QrPayloadShapePolicy;
import com.cybershield.engine.policies.qr.UpiCollectMandatePolicy;
import com.cybershield.engine.policies.qr.UpiPaymentPolicy;
import com.cybershield.engine.policies.text.CryptoScamPolicy;
import com.cybershield.engine.policies.text.DigitalArrestPolicy;
import com.cybershield.engine.policies.text.ImpersonationPolicy;
import com.cybershield.engine.policies.text.OtpRequestPolicy;
import com.cybershield.engine.policies.text.PrizeJobScamPolicy;
import com.cybershield.engine.policies.text.ReceiveMoneyScamPolicy;
import com.cybershield.engine.policies.text.UrgencyAndCredentialPolicy;
import com.cybershield.engine.policies.url.AllowlistUrlPolicy;
import com.cybershield.engine.policies.url.BlocklistUrlPolicy;
import com.cybershield.engine.policies.url.DeceptiveSubdomainPolicy;
import com.cybershield.engine.policies.url.InsecureTransportPolicy;
import com.cybershield.engine.policies.url.IpAddressHostPolicy;
import com.cybershield.engine.policies.url.MlUrlScorePolicy;
import com.cybershield.engine.policies.url.PunycodeHomographPolicy;
import com.cybershield.engine.policies.url.SuspiciousTldPolicy;
import com.cybershield.engine.policies.url.TyposquattingPolicy;
import com.cybershield.engine.policies.url.UrlObfuscationPolicy;
import com.cybershield.engine.policies.url.UrlShortenerPolicy;
import com.cybershield.engine.policies.web.LoginFormPolicy;
import com.cybershield.engine.policies.web.PageContentPolicy;
import com.cybershield.core.ml.MlUrlClassifier;
import com.cybershield.intel.LocalIntelStore;
import com.cybershield.qr.UpiUri;
import com.cybershield.app.net.dto.AnalyzeResponse;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.UUID;

/**
 * The backend detection pipeline, running entirely on the phone. Produces the
 * same {@link AnalyzeResponse} shape the app used to get over REST, so nothing
 * downstream changes — and it needs no network.
 */
public final class OnDeviceAnalyzer {

    private final ContextBuilder contextBuilder = new ContextBuilder();
    private final RiskScorer scorer = new RiskScorer();
    private final ExplanationService explanations = new ExplanationService();
    private final DetectionEngine engine;
    private final LocalIntelStore intel;

    public OnDeviceAnalyzer(Context ctx) {
        this.intel = new LocalIntelStore(ctx.getApplicationContext());
        MlUrlClassifier mlUrl = new MlUrlClassifier(ctx.getApplicationContext());
        List<Policy> policies = Arrays.asList(
                // URL / link
                new TyposquattingPolicy(intel),
                new PunycodeHomographPolicy(),
                new IpAddressHostPolicy(),
                new DeceptiveSubdomainPolicy(intel),
                new UrlShortenerPolicy(intel),
                new UrlObfuscationPolicy(),
                new SuspiciousTldPolicy(intel),
                new InsecureTransportPolicy(),
                new BlocklistUrlPolicy(intel),
                new AllowlistUrlPolicy(intel),
                new MlUrlScorePolicy(mlUrl, intel),
                // message / text
                new UrgencyAndCredentialPolicy(),
                new OtpRequestPolicy(),
                new ReceiveMoneyScamPolicy(),
                new ImpersonationPolicy(),
                new PrizeJobScamPolicy(),
                new CryptoScamPolicy(),
                new DigitalArrestPolicy(),
                // email headers (SPF/DKIM/DMARC, sender spoofing) — offline, no RDAP
                new DisplayNameSpoofPolicy(intel),
                new AuthResultsPolicy(),
                new ReplyToMismatchPolicy(),
                new SenderLookAlikePolicy(intel),
                // QR / UPI
                new UpiPaymentPolicy(intel),
                new UpiCollectMandatePolicy(),
                new QrPayloadShapePolicy(),
                // web page
                new LoginFormPolicy(),
                new PageContentPolicy());
        this.engine = new DetectionEngine(policies);
    }

    public AnalyzeResponse analyze(String typeName, String content, String pageUrl) {
        ContentType type = parseType(typeName);
        ContextBuilder.Built built = contextBuilder.build(type, content, pageUrl);

        List<Signal> signals = engine.run(built.context());
        Verdict v = new Verdict();
        for (Signal s : signals) v.addSignal(s);

        int score = scorer.score(signals);
        v.setRiskScore(score);
        v.setRiskLevel(scorer.level(score));
        v.setConfidence(scorer.confidence(signals, built.hadNetworkData()));

        built.context().primaryUrl().ifPresent(u -> {
            boolean nothingNegative = signals.stream().noneMatch(s -> s.weight() > 0);
            if (intel.isAllowedDomain(u.host()) && nothingNegative) v.setTrusted(true);
        });

        UpiUri upi = built.upi();
        boolean initiatesPayment = upi != null && upi.initiatesDebit();
        explanations.enrich(v, type, upi, initiatesPayment);

        return toResponse(type, v, upi, initiatesPayment);
    }

    private AnalyzeResponse toResponse(ContentType type, Verdict v, UpiUri upi, boolean initiatesPayment) {
        AnalyzeResponse r = new AnalyzeResponse();
        r.reportId = UUID.randomUUID().toString();
        r.contentType = type.name();
        r.riskScore = v.getRiskScore();
        r.riskLevel = v.getRiskLevel().name();
        r.priority = v.getRiskLevel().priority();
        r.wording = v.wording();
        r.confidence = v.getConfidence();
        r.verified = v.isVerified();
        r.trusted = v.isTrusted();
        r.initiatesPayment = initiatesPayment;
        r.categories = new ArrayList<>(v.getCategories());
        r.explanation = v.getExplanation();
        r.recommendations = new ArrayList<>(v.getRecommendations());

        r.signals = new ArrayList<>();
        for (Signal s : v.getSignals()) {
            AnalyzeResponse.Signal dto = new AnalyzeResponse.Signal();
            dto.policyId = s.policyId();
            dto.name = s.name();
            dto.detail = s.detail();
            dto.severity = s.severity().name();
            dto.weight = s.weight();
            r.signals.add(dto);
        }

        if (upi != null && upi.valid()) {
            AnalyzeResponse.PaymentInfo p = new AnalyzeResponse.PaymentInfo();
            p.scheme = "UPI";
            p.action = upi.action();
            p.payeeVpa = upi.payeeVpa().orElse(null);
            p.payeeName = upi.payeeName().orElse(null);
            p.amount = upi.amount().orElse(null);
            p.currency = upi.currency().orElse("INR");
            p.note = upi.note().orElse(null);
            p.pullPayment = upi.isCollectOrMandate();
            r.payment = p;
        }

        SimpleDateFormat iso = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US);
        iso.setTimeZone(TimeZone.getTimeZone("UTC"));
        r.analyzedAt = iso.format(new Date());
        return r;
    }

    private static ContentType parseType(String name) {
        if (name == null) return ContentType.URL;
        try {
            return ContentType.valueOf(name.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return ContentType.URL;
        }
    }
}
