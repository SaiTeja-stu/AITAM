package com.cybershield.app.net.dto;

import java.util.ArrayList;
import java.util.List;

/** Mirrors the backend AnalyzeResponse record. */
public class AnalyzeResponse {
    public String reportId;
    public String contentType;
    public int riskScore;
    public String riskLevel;     // SAFE | SUSPICIOUS | HIGH_RISK | MALICIOUS
    public String priority;      // P1..P4
    public String wording;
    public int confidence;
    public boolean verified;
    public boolean trusted;
    public boolean initiatesPayment;
    public List<String> categories = new ArrayList<>();
    public List<Signal> signals = new ArrayList<>();
    public String explanation;
    public List<String> recommendations = new ArrayList<>();
    public PaymentInfo payment;
    public String analyzedAt;

    public boolean isBlocking() {
        return "MALICIOUS".equals(riskLevel) || "HIGH_RISK".equals(riskLevel);
    }

    public static class Signal {
        public String policyId;
        public String name;
        public String detail;
        public String severity;  // CRITICAL | HIGH | MEDIUM | LOW | TRUST
        public int weight;
    }

    public static class PaymentInfo {
        public String scheme;
        public String action;
        public String payeeVpa;
        public String payeeName;
        public Double amount;
        public String currency;
        public String note;
        public boolean pullPayment;
    }
}
