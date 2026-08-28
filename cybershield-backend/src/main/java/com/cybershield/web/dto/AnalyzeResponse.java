package com.cybershield.web.dto;

import java.time.Instant;
import java.util.List;

/** The verdict returned to clients. */
public record AnalyzeResponse(
        String reportId,
        String contentType,
        int riskScore,
        String riskLevel,      // SAFE / SUSPICIOUS / HIGH_RISK / MALICIOUS
        String priority,       // P1..P4
        String wording,        // user-facing label per the evidence ladder
        int confidence,
        boolean verified,
        boolean trusted,
        boolean initiatesPayment,
        List<String> categories,
        List<SignalDto> signals,
        String explanation,
        List<String> recommendations,
        PaymentInfo payment,   // non-null only for UPI QR
        Instant analyzedAt
) {
    public record SignalDto(String policyId, String name, String detail, String severity, int weight) {}

    public record PaymentInfo(
            String scheme,        // "UPI"
            String action,        // pay / collect / mandate
            String payeeVpa,      // shown to user, not stored server-side in plaintext
            String payeeName,
            Double amount,
            String currency,
            String note,
            boolean pullPayment
    ) {}
}
