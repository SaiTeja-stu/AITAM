package com.cybershield.app.net.dto;

import java.util.ArrayList;
import java.util.List;

/** Generic paged response { items, page, size, totalElements, totalPages }. */
public class Page<T> {
    public List<T> items = new ArrayList<>();
    public int page;
    public int size;
    public long totalElements;
    public int totalPages;

    public static class ScanItem {
        public String reportId;
        public String type;
        public int riskScore;
        public String riskLevel;
        public String priority;
        public int confidence;
        public boolean verified;
        public String snippet;
        public String analyzedAt;
    }

    public static class ReportItem {
        public String id;
        public String type;
        public String snippet;
        public String indicatorType;
        public String indicatorValue;
        public String note;
        public String status;
        public String createdAt;
    }
}
