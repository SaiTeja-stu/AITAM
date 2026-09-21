package com.cybershield.app.net.dto;

/** Mirrors the backend's incident-report response map. */
public class IncidentReportResponse {
    public String incidentId;
    public String status;
    public String evidenceSha256;
    public String timestamp;
    public String jurisdictionStation;
    public String helpline;
    public String receiptToken;
}
