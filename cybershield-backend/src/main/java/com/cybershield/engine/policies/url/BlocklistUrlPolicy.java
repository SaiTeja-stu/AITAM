package com.cybershield.engine.policies.url;

import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;
import com.cybershield.intel.LocalIntelStore;
import com.cybershield.intel.ThreatFeedService;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/** URL-10: the domain is on a threat blocklist, a live feed, or confirmed community reports. */
@Component
public class BlocklistUrlPolicy extends AbstractPolicy {

    private final LocalIntelStore intel;
    private final ThreatFeedService feeds;

    public BlocklistUrlPolicy(LocalIntelStore intel, ThreatFeedService feeds) {
        super("URL-10", URL_LIKE);
        this.intel = intel;
        this.feeds = feeds;
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        List<Signal> out = new ArrayList<>();
        for (var u : ctx.allUrls()) {
            if (intel.isBlockedDomain(u.host())) {
                out.add(signal("Known malicious site",
                        "The domain '" + u.host() + "' appears on a threat blocklist or has been reported by users.",
                        Severity.CRITICAL, 55));
                continue;
            }
            ThreatFeedService.Hit hit = feeds.check(u.original(), u.host());
            if (hit.malicious()) {
                out.add(signal("Flagged by " + hit.source(),
                        "'" + u.host() + "' is listed as malicious by " + hit.source() + " right now.",
                        Severity.CRITICAL, 55));
            }
        }
        return out;
    }
}
