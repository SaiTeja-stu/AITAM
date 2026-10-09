package com.cybershield.app.net.dto;

/** Mirrors the backend ForensicsController.IncidentReportRequest record with nullable coordinates. */
public class IncidentReportRequest {
    public String evidenceSha256;
    public String subject;
    public String sender;
    public String riskTier;
    public Integer riskScore;
    public Double userLat;
    public Double userLon;
    public Float accuracyMeters;
    public String networkProvider;
    public String reporterNotes;

    public IncidentReportRequest(String evidenceSha256, String subject, String sender,
                                  String riskTier, Integer riskScore, Double userLat, Double userLon,
                                  Float accuracyMeters, String networkProvider, String reporterNotes) {
        this.evidenceSha256 = evidenceSha256;
        this.subject = subject;
        this.sender = sender;
        this.riskTier = riskTier;
        this.riskScore = riskScore;
        this.userLat = userLat;
        this.userLon = userLon;
        this.accuracyMeters = accuracyMeters;
        this.networkProvider = networkProvider;
        this.reporterNotes = reporterNotes;
    }
}
