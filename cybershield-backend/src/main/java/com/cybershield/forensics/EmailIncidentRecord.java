package com.cybershield.forensics;

import jakarta.persistence.*;

import java.time.Instant;

/**
 * Hot-tier record of one analyzed email, kept only for cross-email campaign
 * correlation: "has this sender domain or origin IP shown up before?"
 */
@Entity
@Table(name = "email_incident_record", indexes = {
        @Index(name = "ix_incident_domain", columnList = "fromDomain"),
        @Index(name = "ix_incident_origin_ip", columnList = "originIp"),
        @Index(name = "ix_incident_created", columnList = "createdAt")
})
public class EmailIncidentRecord {

    @Id
    @Column(length = 36)
    private String id;

    @Column(nullable = false, length = 255)
    private String fromDomain;

    @Column(nullable = false, length = 64)
    private String originIp;

    @Column(length = 128)
    private String originCountry;

    @Column(nullable = false, length = 16)
    private String riskTier;

    @Column(nullable = false, length = 320)
    private String messageId;

    @Column(nullable = false, length = 80)
    private String evidenceSha256;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getFromDomain() { return fromDomain; }
    public void setFromDomain(String fromDomain) { this.fromDomain = fromDomain; }
    public String getOriginIp() { return originIp; }
    public void setOriginIp(String originIp) { this.originIp = originIp; }
    public String getOriginCountry() { return originCountry; }
    public void setOriginCountry(String originCountry) { this.originCountry = originCountry; }
    public String getRiskTier() { return riskTier; }
    public void setRiskTier(String riskTier) { this.riskTier = riskTier; }
    public String getMessageId() { return messageId; }
    public void setMessageId(String messageId) { this.messageId = messageId; }
    public String getEvidenceSha256() { return evidenceSha256; }
    public void setEvidenceSha256(String evidenceSha256) { this.evidenceSha256 = evidenceSha256; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
