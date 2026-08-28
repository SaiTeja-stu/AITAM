package com.cybershield.scan;

import com.cybershield.domain.ContentType;
import com.cybershield.domain.RiskLevel;
import jakarta.persistence.*;

import java.time.Instant;

/**
 * Hot-tier record of one analysis. Holds only a content HASH and a short
 * redacted snippet - never the full original content (trust policy T-03).
 * The full immutable record lives in the cold-tier JSONL log.
 */
@Entity
@Table(name = "scan_record", indexes = {
        @Index(name = "ix_scan_created", columnList = "createdAt"),
        @Index(name = "ix_scan_owner", columnList = "ownerId"),
        @Index(name = "ix_scan_hash", columnList = "contentHash")
})
public class ScanRecord {

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

    @Column(nullable = false)
    private int riskScore;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private RiskLevel riskLevel;

    @Column(nullable = false, length = 8)
    private String priority;

    @Column(nullable = false)
    private int confidence;

    @Column(nullable = false)
    private boolean verified;

    @Column(length = 64)
    private String ownerId;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    public ScanRecord() {}

    // getters / setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public ContentType getType() { return type; }
    public void setType(ContentType type) { this.type = type; }
    public String getContentHash() { return contentHash; }
    public void setContentHash(String contentHash) { this.contentHash = contentHash; }
    public String getSnippet() { return snippet; }
    public void setSnippet(String snippet) { this.snippet = snippet; }
    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
    public RiskLevel getRiskLevel() { return riskLevel; }
    public void setRiskLevel(RiskLevel riskLevel) { this.riskLevel = riskLevel; }
    public String getPriority() { return priority; }
    public void setPriority(String priority) { this.priority = priority; }
    public int getConfidence() { return confidence; }
    public void setConfidence(int confidence) { this.confidence = confidence; }
    public boolean isVerified() { return verified; }
    public void setVerified(boolean verified) { this.verified = verified; }
    public String getOwnerId() { return ownerId; }
    public void setOwnerId(String ownerId) { this.ownerId = ownerId; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
