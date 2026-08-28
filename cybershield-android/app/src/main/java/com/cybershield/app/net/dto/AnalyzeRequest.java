package com.cybershield.app.net.dto;

/** Mirrors the backend AnalyzeRequest record. */
public class AnalyzeRequest {
    public String type;      // URL | EMAIL | SMS | QR | WEBPAGE | SOCIAL
    public String content;
    public String pageUrl;
    public String source;

    public AnalyzeRequest(String type, String content, String source) {
        this.type = type;
        this.content = content;
        this.source = source;
    }
}
