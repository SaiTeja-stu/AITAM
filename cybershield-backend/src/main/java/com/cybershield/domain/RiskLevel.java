package com.cybershield.domain;

/**
 * Risk classification mapped from the 0-100 risk score, with an operational
 * priority (P1-P4) and the user-facing wording rules from the spec.
 *
 * Wording rules:
 *  - Never claim "100% authorised / safe / genuine".
 *  - "Verified" / "Trusted" require positive evidence and are set explicitly
 *    by the engine, not derived from a low score. See Verdict.verified /
 *    Verdict.trusted. This enum only covers the risk-score-derived wording.
 */
public enum RiskLevel {

    SAFE("P4", 0, 24, "No suspicious indicators detected"),
    SUSPICIOUS("P3", 25, 49, "Potentially risky"),
    HIGH_RISK("P2", 50, 74, "High-risk recipient"),
    MALICIOUS("P1", 75, 100, "High-risk recipient");

    private final String priority;
    private final int minScore;
    private final int maxScore;
    private final String defaultWording;

    RiskLevel(String priority, int minScore, int maxScore, String defaultWording) {
        this.priority = priority;
        this.minScore = minScore;
        this.maxScore = maxScore;
        this.defaultWording = defaultWording;
    }

    public String priority() { return priority; }
    public String defaultWording() { return defaultWording; }
    public int minScore() { return minScore; }
    public int maxScore() { return maxScore; }

    public static RiskLevel fromScore(int score) {
        int s = Math.max(0, Math.min(100, score));
        for (RiskLevel level : values()) {
            if (s >= level.minScore && s <= level.maxScore) {
                return level;
            }
        }
        return MALICIOUS;
    }
}
