package com.cybershield.app.net.dto;

import java.util.List;
import java.util.Map;

/** Mirrors the backend EmailForensicsService.ForensicAnalysisResult record. */
public class ForensicsResult {
    public String evidenceSha256;
    public String analyzedAt;
    public String fromDisplay;
    public String fromAddress;
    public String fromDomain;
    public String replyTo;
    public String returnPath;
    public String subject;
    public String date;
    public String messageId;
    public String bodySnippet;
    public List<RelayHop> relayHops;
    public RelayHop originatingHop;
    public Map<String, AuthStatus> authMatrix;
    public int overallRiskScore;
    public String riskTier;
    public List<String> riskFactors;
    public int becScore;
    public boolean isVipImpersonation;
    public boolean hasFinancialCoercion;
    public List<String> extractedUrls;
    public List<AttachmentForensic> attachments;
    public List<GraphNode> graphNodes;
    public List<GraphEdge> graphEdges;
    public String section65bLegalSummary;
    public List<CampaignMatch> campaignMatches;

    public static class GeoData {
        public String ip;
        public String city;
        public String region;
        public String country;
        public String countryCode;
        public double latitude;
        public double longitude;
        public String asn;
        public String isp;
        public boolean isDatacenter;
        public boolean isTorOrProxy;
        public boolean isPrivate;
        public int riskScore;
        public String riskReason;
    }

    public static class RelayHop {
        public int hopNumber;
        public String rawHopText;
        public String ip;
        public String host;
        public GeoData geo;
        public long delaySeconds;
        public boolean isOriginating;
        public boolean isSuspicious;
    }

    public static class AuthStatus {
        public String status;
        public String mechanism;
        public String domainEvaluated;
        public boolean alignedWithFrom;
        public String details;
    }

    public static class AttachmentForensic {
        public String filename;
        public String extension;
        public long sizeBytes;
        public String md5Hash;
        public String sha256Hash;
        public boolean isDoubleExtension;
        public boolean isHighRiskExecutable;
        public String riskWarning;
    }

    public static class GraphNode {
        public String id, label, type;
        public int risk;
    }

    public static class GraphEdge {
        public String source, target, relationship;
    }

    public static class CampaignMatch {
        public String messageId;
        public String fromDomain;
        public String originIp;
        public String riskTier;
        public String matchedOn;
        public String seenAt;
    }
}
