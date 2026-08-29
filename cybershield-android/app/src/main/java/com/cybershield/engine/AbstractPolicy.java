package com.cybershield.engine;

import com.cybershield.domain.ContentType;
import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;

import java.util.List;
import java.util.Set;

/** Convenience base: fixed id/appliesTo, exception-safe evaluate wrapper. */
public abstract class AbstractPolicy implements Policy {

    private final String id;
    private final Set<ContentType> appliesTo;

    protected AbstractPolicy(String id, Set<ContentType> appliesTo) {
        this.id = id;
        this.appliesTo = appliesTo;
    }

    @Override public String id() { return id; }
    @Override public Set<ContentType> appliesTo() { return appliesTo; }

    @Override
    public final List<Signal> evaluate(PolicyContext ctx) {
        try {
            List<Signal> out = doEvaluate(ctx);
            return out == null ? List.of() : out;
        } catch (RuntimeException e) {
            return List.of();   // policies must never throw for hostile input
        }
    }

    protected abstract List<Signal> doEvaluate(PolicyContext ctx);

    protected Signal signal(String name, String detail, Severity severity, int weight) {
        return Signal.of(id, name, detail, severity, weight);
    }

    protected List<Signal> one(String name, String detail, Severity severity, int weight) {
        return List.of(signal(name, detail, severity, weight));
    }

    protected static final Set<ContentType> URL_LIKE =
            Set.of(ContentType.URL, ContentType.WEBPAGE, ContentType.QR,
                   ContentType.EMAIL, ContentType.SMS, ContentType.SOCIAL);
    protected static final Set<ContentType> TEXT_LIKE =
            Set.of(ContentType.EMAIL, ContentType.SMS, ContentType.SOCIAL, ContentType.QR);
}
