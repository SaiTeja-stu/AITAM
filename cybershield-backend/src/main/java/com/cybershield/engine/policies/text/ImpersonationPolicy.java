package com.cybershield.engine.policies.text;

import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;
import org.springframework.stereotype.Component;

import java.util.List;

/** MSG-06: message impersonates a bank / government body / courier / large brand. */
@Component
public class ImpersonationPolicy extends AbstractPolicy {

    public ImpersonationPolicy() {
        super("MSG-06", TEXT_LIKE);
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        String t = Keywords.lower(ctx.text().isBlank() ? ctx.rawContent() : ctx.text());
        if (t.isBlank()) return List.of();

        boolean entity = Keywords.containsAny(t, Keywords.IMPERSONATION_ENTITIES);
        boolean demand = t.contains("verify") || t.contains("update") || t.contains("pay")
                || t.contains("penalty") || t.contains("blocked") || t.contains("suspended")
                || t.contains("pending") || t.contains("click");
        if (entity && demand) {
            return one("Impersonates an official organisation",
                    "The message claims to be from an authority or well-known company and pairs that with a demand or threat.",
                    Severity.HIGH, 24);
        }
        return List.of();
    }
}
