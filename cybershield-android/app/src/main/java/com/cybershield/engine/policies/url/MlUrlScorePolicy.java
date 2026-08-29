package com.cybershield.engine.policies.url;

import com.cybershield.core.ml.MlUrlClassifier;
import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;
import com.cybershield.intel.LocalIntelStore;

import java.util.ArrayList;
import java.util.List;

/**
 * URL-13: on-device trained lexical model, folded in as ONE capped signal
 * (max +18, never CRITICAL). Mirrors the backend policy of the same id.
 */
public class MlUrlScorePolicy extends AbstractPolicy {

    private static final double FLOOR = 0.55;
    private static final double HIGH = 0.85;
    private static final int CAP = 22;

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
