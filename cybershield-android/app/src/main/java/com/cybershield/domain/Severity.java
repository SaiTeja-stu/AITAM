package com.cybershield.domain;

/**
 * Severity band for a detection policy. Each band maps to a default weight range;
 * a policy supplies its concrete weight within (or near) its band.
 * TRUST is a negative-weight band used by allowlist / known-good policies.
 */
public enum Severity {
    TRUST(-40, -10),
    LOW(3, 8),
    MEDIUM(10, 20),
    HIGH(20, 35),
    CRITICAL(40, 60);

    private final int minWeight;
    private final int maxWeight;

    Severity(int minWeight, int maxWeight) {
        this.minWeight = minWeight;
        this.maxWeight = maxWeight;
    }

    public int minWeight() { return minWeight; }
    public int maxWeight() { return maxWeight; }

    /** Clamp an arbitrary weight into this severity's band. */
    public int clamp(int weight) {
        return Math.max(minWeight, Math.min(maxWeight, weight));
    }
}
