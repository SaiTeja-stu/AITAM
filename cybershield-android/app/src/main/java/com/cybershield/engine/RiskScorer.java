package com.cybershield.engine;

import com.cybershield.domain.RiskLevel;
import com.cybershield.domain.Signal;

import java.util.List;

/**
 * Turns a list of fired signals into a 0-100 risk score, a {@link RiskLevel},
 * and a confidence value.
 *
 * Formula (spec section C):
 *   raw   = sum(positive weights) - sum(trust offsets)
 *   score = clamp(0, 100, raw)
 *   if any CRITICAL signal fired -> score = max(score, 80)
 */
public class RiskScorer {

    public int score(List<Signal> signals) {
        int raw = signals.stream().mapToInt(Signal::weight).sum();
        int score = Math.max(0, Math.min(100, raw));
        boolean critical = signals.stream().anyMatch(Signal::isCritical);
        if (critical) {
            score = Math.max(score, 80);
        }
        return score;
    }

    public RiskLevel level(int score) {
        return RiskLevel.fromScore(score);
    }

    /**
     * Confidence reflects how much evidence we had, not how bad it is.
     * Low when nothing fired or only weak heuristics; high when authoritative
     * signals (blocklist / community reports / structured payment data) were present.
     */
    public int confidence(List<Signal> signals, boolean hadNetworkData) {
        if (signals.isEmpty()) return hadNetworkData ? 55 : 35;
        int base = 45;
        for (Signal s : signals) {
            switch (s.severity()) {
                case CRITICAL -> base += 20;
                case HIGH -> base += 10;
                case MEDIUM -> base += 6;
                case LOW -> base += 3;
                case TRUST -> base += 12;
            }
        }
        if (hadNetworkData) base += 10;
        return Math.max(20, Math.min(99, base));
    }
}
