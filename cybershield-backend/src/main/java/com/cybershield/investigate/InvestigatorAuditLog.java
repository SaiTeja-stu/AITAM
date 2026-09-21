package com.cybershield.investigate;

import jakarta.persistence.*;

import java.time.Instant;

/**
 * Accountability trail for the cyber-cell investigator console (trust policy:
 * every cross-user lookup must be attributable). Records who searched what
 * indicator and when - never the search results themselves.
 */
@Entity
@Table(name = "investigator_audit_log", indexes = {
        @Index(name = "ix_audit_investigator", columnList = "investigatorId"),
        @Index(name = "ix_audit_searched_at", columnList = "searchedAt")
})
public class InvestigatorAuditLog {

    @Id
    @Column(length = 36)
    private String id;

    @Column(nullable = false, length = 36)
    private String investigatorId;

    @Column(nullable = false, length = 64)
    private String investigatorUsername;

    @Column(nullable = false, length = 16)
    private String indicatorType;

    /** The suspect indicator searched (a domain, hashed VPA, hashed phone...) - never victim PII. */
    @Column(nullable = false, length = 200)
    private String indicatorValue;

    @Column(nullable = false)
    private int resultCount;

    @Column(length = 64)
    private String requestIp;

    @Column(nullable = false)
    private Instant searchedAt = Instant.now();

    public InvestigatorAuditLog() {}

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getInvestigatorId() { return investigatorId; }
    public void setInvestigatorId(String investigatorId) { this.investigatorId = investigatorId; }
    public String getInvestigatorUsername() { return investigatorUsername; }
    public void setInvestigatorUsername(String investigatorUsername) { this.investigatorUsername = investigatorUsername; }
    public String getIndicatorType() { return indicatorType; }
    public void setIndicatorType(String indicatorType) { this.indicatorType = indicatorType; }
    public String getIndicatorValue() { return indicatorValue; }
    public void setIndicatorValue(String indicatorValue) { this.indicatorValue = indicatorValue; }
    public int getResultCount() { return resultCount; }
    public void setResultCount(int resultCount) { this.resultCount = resultCount; }
    public String getRequestIp() { return requestIp; }
    public void setRequestIp(String requestIp) { this.requestIp = requestIp; }
    public Instant getSearchedAt() { return searchedAt; }
    public void setSearchedAt(Instant searchedAt) { this.searchedAt = searchedAt; }
}
