package com.cybershield.domain;

/**
 * One piece of evidence contributing to the verdict. Surfaced to the user for
 * transparency (trust policy T-01) and used by the scorer.
 *
 * @param policyId stable identifier, e.g. "URL-01"
 * @param name     short human label, e.g. "Typosquatting"
 * @param detail   plain-language explanation of what was found
 * @param severity severity band
 * @param weight   signed contribution to the raw score (negative for TRUST signals)
 */
public record Signal(String policyId, String name, String detail, Severity severity, int weight) {

    public static Signal of(String policyId, String name, String detail, Severity severity, int weight) {
        return new Signal(policyId, name, detail, severity, severity.clamp(weight));
    }

    public boolean isCritical() {
        return severity == Severity.CRITICAL;
    }

    public boolean isTrust() {
        return severity == Severity.TRUST;
    }
}
