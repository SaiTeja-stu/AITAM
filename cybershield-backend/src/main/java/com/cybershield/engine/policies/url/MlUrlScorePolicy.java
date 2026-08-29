package com.cybershield.engine.policies.url;

import com.cybershield.analyze.ml.MlUrlClassifier;
import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;
import com.cybershield.intel.LocalIntelStore;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * URL-13: a trained lexical model's opinion, folded in as ONE capped signal.
 *
 * <p>The model ({@code ml/url_model.json}) returns a phishing probability from the
 * URL's structure — length, entropy, digit ratio, subdomain depth, credential
 * keywords, {@code @}, punycode, suspicious TLD, etc. It is deliberately capped
 * (max +18) and never CRITICAL: it nudges the score and adds an explanation, but
 * the rule-based policies and threat intelligence remain the backbone of the
 * verdict. Known-good (allowlisted) domains are skipped.
 */
@Component
public class MlUrlScorePolicy extends AbstractPolicy {

    private static final double FLOOR = 0.55;   // below this: no signal
    private static final double HIGH = 0.85;    // at/above this: HIGH severity
    private static final int CAP = 22;          // the model can never contribute more than this

    private final MlUrlClassifier model;
    private final LocalIntelStore intel;

    public MlUrlScorePolicy(MlUrlClassifier model, LocalIntelStore intel) {
        super("URL-13", URL_LIKE);
        this.model = model;
        this.intel = intel;
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        if (!model.isReady()) return List.of();
        List<Signal> out = new ArrayList<>();
        double best = -1;
        String bestUrl = null;
        for (var u : ctx.allUrls()) {
            if (intel.isAllowedDomain(u.host())) continue;
            double p = model.probability(u.original());
            if (p > best) { best = p; bestUrl = u.original(); }
        }
        if (best < FLOOR || bestUrl == null) return out;

        int pct = (int) Math.round(best * 100);
        int weight = (int) Math.round(best * 26);
        Severity sev = best >= HIGH ? Severity.HIGH : Severity.MEDIUM;
        String anomaly = model.anomalyNote(bestUrl);

        String detail = "A lexical risk model rates this link ~" + pct + "% consistent with phishing/scam URLs "
                + "(structure, keywords, entropy, subdomain depth)"
                + (anomaly.isEmpty() ? "." : "; also: " + anomaly + ".");

        out.add(signal("Machine-learning URL risk", detail, sev, Math.min(CAP, weight)));
        return out;
    }
}
