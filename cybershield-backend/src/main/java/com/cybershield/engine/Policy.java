package com.cybershield.engine;

import com.cybershield.domain.ContentType;
import com.cybershield.domain.Signal;

import java.util.List;
import java.util.Set;

/**
 * A single detection rule. Implementations must be deterministic (trust policy
 * T-07): the same {@link PolicyContext} must always yield the same signals.
 */
public interface Policy {

    /** Stable identifier, e.g. "URL-01". */
    String id();

    /** Content types this policy applies to. */
    Set<ContentType> appliesTo();

    /**
     * Evaluate the context. Return zero or more signals (usually 0 or 1).
     * Must never throw for hostile input — catch and return empty.
     */
    List<Signal> evaluate(PolicyContext ctx);

    default boolean supports(ContentType type) {
        return appliesTo().contains(type);
    }
}
