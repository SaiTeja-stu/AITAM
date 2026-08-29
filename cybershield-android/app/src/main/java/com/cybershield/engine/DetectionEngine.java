package com.cybershield.engine;

import com.cybershield.domain.Signal;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/** Runs every applicable {@link Policy} against a context and collects the signals. */
public class DetectionEngine {

    private final List<Policy> policies;

    public DetectionEngine(List<Policy> policies) {
        this.policies = policies;
    }

    public List<Signal> run(PolicyContext ctx) {
        List<Signal> signals = new ArrayList<>();
        for (Policy p : policies) {
            if (!p.supports(ctx.type())) continue;
            List<Signal> fired = p.evaluate(ctx);
            if (fired != null && !fired.isEmpty()) {
                signals.addAll(fired);
            }
        }
        // Strongest first for display (trust policy T-01).
        signals.sort(Comparator.comparingInt((Signal s) -> s.weight()).reversed());
        return signals;
    }
}
