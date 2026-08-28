package com.cybershield.report;

import com.cybershield.domain.ContentType;
import com.cybershield.intel.IndicatorType;
import jakarta.persistence.*;

import java.time.Instant;

/** A user-submitted threat report (problem statement: "Threat reporting"). */
@Entity
@Table(name = "threat_report", indexes = {
        @Index(name = "ix_report_hash", columnList = "contentHash"),
        @Index(name = "ix_report_status", columnList = "status")
})
public class ThreatReport {

    public enum Status { PENDING, CONFIRMED, REJECTED }

    @Id
    @Column(length = 36)
    private String id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private ContentType type;

    @Column(nullable = false, length = 80)
    private String contentHash;

    @Column(length = 320)
    private String snippet;

    /** Extracted indicator for community matching (domain, hashed VPA, ...). */
    @Enumerated(EnumType.STRING)
    @Column(length = 16)
    private IndicatorType indicatorType;

    @Column(length = 200)
    private String indicatorValue;

    @Column(length = 400)
    private String reporterNote;

    @Column(length = 64)
    private String reporterId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private Status status = Status.PENDING;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    public ThreatReport() {}

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public ContentType getType() { return type; }
    public void setType(ContentType type) { this.type = type; }
    public String getContentHash() { return contentHash; }
    public void setContentHash(String contentHash) { this.contentHash = contentHash; }
    public String getSnippet() { return snippet; }
    public void setSnippet(String snippet) { this.snippet = snippet; }
    public IndicatorType getIndicatorType() { return indicatorType; }
    public void setIndicatorType(IndicatorType indicatorType) { this.indicatorType = indicatorType; }
    public String getIndicatorValue() { return indicatorValue; }
    public void setIndicatorValue(String indicatorValue) { this.indicatorValue = indicatorValue; }
    public String getReporterNote() { return reporterNote; }
    public void setReporterNote(String reporterNote) { this.reporterNote = reporterNote; }
    public String getReporterId() { return reporterId; }
    public void setReporterId(String reporterId) { this.reporterId = reporterId; }
    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
