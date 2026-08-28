package com.cybershield.app.net.dto;

public class ReportRequest {
    public String type;
    public String content;
    public String note;

    public ReportRequest(String type, String content, String note) {
        this.type = type;
        this.content = content;
        this.note = note;
    }
}
