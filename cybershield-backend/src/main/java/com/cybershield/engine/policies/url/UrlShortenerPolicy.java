package com.cybershield.engine.policies.url;

import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;
import com.cybershield.intel.LocalIntelStore;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/** URL-06: link uses a URL shortener that hides the true destination. */
@Component
public class UrlShortenerPolicy extends AbstractPolicy {

    private final LocalIntelStore intel;

    public UrlShortenerPolicy(LocalIntelStore intel) {
        super("URL-06", URL_LIKE);
        this.intel = intel;
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        List<Signal> out = new ArrayList<>();
        for (var u : ctx.allUrls()) {
            if (intel.isShortener(u.host())) {
                out.add(signal("Shortened link",
                        "'" + u.host() + "' is a link shortener; the real destination is hidden until you open it.",
                        Severity.MEDIUM, 12));
            }
        }
        return out;
    }
}
