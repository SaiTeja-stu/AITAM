package com.cybershield.domain;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The full result of analysing one piece of content.
 *
 * <p>Wording invariants (from spec):
 * <ul>
 *   <li>{@link #verified} may only be {@code true} when an authoritative source
 *       positively confirmed the recipient/site. Never derived from a low score.</li>
 *   <li>{@link #trusted} may only be {@code true} when the target is on a curated
 *       allowlist AND no negative signals fired.</li>
 *   <li>{@link #wording()} is the single string the client should show; it degrades
 *       gracefully and never says "100% safe/authorised".</li>
 * </ul>
 */
public final class Verdict {

    private int riskScore;
    private int confidence;
    private RiskLevel riskLevel;
    private boolean verified;
    private boolean trusted;
    private final List<Signal> signals = new ArrayList<>();
    private final List<String> categories = new ArrayList<>();
    private String explanation = "";
    private final List<String> recommendations = new ArrayList<>();

    public void addSignal(Signal s) {
        if (s != null) signals.add(s);
    }

    public void addCategory(String c) {
        if (c != null && !categories.contains(c)) categories.add(c);
    }

    public void addRecommendation(String r) {
        if (r != null && !recommendations.contains(r)) recommendations.add(r);
    }

    /** Resolve the user-facing wording per the spec's evidence ladder. */
    public String wording() {
        if (verified) return "Verified";
        if (trusted && signals.stream().noneMatch(s -> s.weight() > 0)) return "Trusted";
        return riskLevel == null ? "No suspicious indicators detected" : riskLevel.defaultWording();
    }

    // --- getters / setters ---
    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }

    public int getConfidence() { return confidence; }
    public void setConfidence(int confidence) { this.confidence = confidence; }

    public RiskLevel getRiskLevel() { return riskLevel; }
    public void setRiskLevel(RiskLevel riskLevel) { this.riskLevel = riskLevel; }

    public boolean isVerified() { return verified; }
    public void setVerified(boolean verified) { this.verified = verified; }

    public boolean isTrusted() { return trusted; }
    public void setTrusted(boolean trusted) { this.trusted = trusted; }

    public List<Signal> getSignals() { return Collections.unmodifiableList(signals); }
    public List<String> getCategories() { return Collections.unmodifiableList(categories); }

    public String getExplanation() { return explanation; }
    public void setExplanation(String explanation) { this.explanation = explanation; }

    public List<String> getRecommendations() { return Collections.unmodifiableList(recommendations); }
}
