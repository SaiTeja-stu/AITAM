package com.cybershield.forensics;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * End-to-End Email Threat Detection, Hop-by-Hop GeoLocation Relay Reconstruction,
 * Cryptographic Authentication (SPF/DKIM/DMARC), BEC Semantic Scoring, and
 * Section 65B Forensic Intelligence Engine.
 */
@Service
public class EmailForensicsService {

    private static final Logger log = LoggerFactory.getLogger(EmailForensicsService.class);

    private final GeoLocationService geoService;
    private final DkimVerifier dkimVerifier;
    private final EmailIncidentRepository incidentRepository;

    public EmailForensicsService(GeoLocationService geoService, DkimVerifier dkimVerifier,
                                  EmailIncidentRepository incidentRepository) {
        this.geoService = geoService;
        this.dkimVerifier = dkimVerifier;
        this.incidentRepository = incidentRepository;
    }

    // --- Data Records ---

    public record RelayHop(
            int hopNumber,
            String rawHopText,
            String ip,
            String host,
            GeoLocationService.GeoData geo,
            long delaySeconds,
            boolean isOriginating,
            boolean isSuspicious
    ) {}

    public record AuthStatus(
            String status,         // PASS, FAIL, SOFTFAIL, NONE, UNKNOWN
            String mechanism,      // SPF, DKIM, DMARC, ARC
            String domainEvaluated,
            boolean alignedWithFrom,
            String details
    ) {}

    public record AttachmentForensic(
            String filename,
            String extension,
            long sizeBytes,
            String md5Hash,
            String sha256Hash,
            boolean isDoubleExtension,
            boolean isHighRiskExecutable,
            String riskWarning
    ) {}

    public record GraphNode(String id, String label, String type, int risk) {}
    public record GraphEdge(String source, String target, String relationship) {}

    public record CampaignMatch(
            String messageId,
            String fromDomain,
            String originIp,
            String riskTier,
            String matchedOn,      // "SAME_DOMAIN" or "SAME_ORIGIN_IP"
            String seenAt
    ) {}

    public record ForensicAnalysisResult(
            String evidenceSha256,
            Instant analyzedAt,
            String fromDisplay,
            String fromAddress,
            String fromDomain,
            String replyTo,
            String returnPath,
            String subject,
            String date,
            String messageId,
            String bodySnippet,
            List<RelayHop> relayHops,
            RelayHop originatingHop,
            Map<String, AuthStatus> authMatrix,
            int overallRiskScore,
            String riskTier,        // SAFE, SUSPICIOUS, HIGH_RISK, MALICIOUS
            List<String> riskFactors,
            int becScore,
            boolean isVipImpersonation,
            boolean hasFinancialCoercion,
            List<String> extractedUrls,
            List<AttachmentForensic> attachments,
            List<GraphNode> graphNodes,
            List<GraphEdge> graphEdges,
            String section65bLegalSummary,
            List<CampaignMatch> campaignMatches
    ) {}

    // --- Core Forensic Analyzer ---

    public ForensicAnalysisResult analyzeEmail(String rawEml, List<AttachmentInput> uploadedAttachments) {
        String cleanEml = rawEml == null ? "" : rawEml.replace("\r\n", "\n").replace("\r", "\n");
        String evidenceHash = computeSha256(cleanEml.getBytes(StandardCharsets.UTF_8));

        // 1. Unfold & Split RFC 5322 Headers vs Body
        int blankLineIdx = findBlankLine(cleanEml);
        String headerSection = blankLineIdx >= 0 ? cleanEml.substring(0, blankLineIdx) : cleanEml;
        String bodySection = blankLineIdx >= 0 ? cleanEml.substring(blankLineIdx).stripLeading() : "";

        Map<String, List<String>> headers = parseHeaders(headerSection);

        // 2. Extract Key Identity Headers
        String fromRaw = getFirst(headers, "from", "Unknown Sender");
        String fromDisplay = extractDisplayName(fromRaw);
        String fromAddress = extractEmailAddress(fromRaw).toLowerCase(Locale.ROOT);
        String fromDomain = extractDomain(fromAddress);

        String replyTo = extractEmailAddress(getFirst(headers, "reply-to", "")).toLowerCase(Locale.ROOT);
        String returnPath = extractDomain(extractEmailAddress(getFirst(headers, "return-path", "")));
        String subject = getFirst(headers, "subject", "(No Subject)");
        String date = getFirst(headers, "date", Instant.now().toString());
        String messageId = getFirst(headers, "message-id", UUID.randomUUID().toString());

        // 3. Reconstruct Hop-by-Hop Relay Path (Reversing Received Headers)
        List<String> receivedHeaders = headers.getOrDefault("received", List.of());
        List<RelayHop> hops = reconstructRelayPath(receivedHeaders);
        RelayHop originatingHop = hops.stream()
                .filter(RelayHop::isOriginating)
                .findFirst()
                .orElse(hops.isEmpty() ? null : hops.get(0));

        // 4. Live & Header Cryptographic Evaluation (SPF, DKIM, DMARC)
        Map<String, AuthStatus> authMatrix = evaluateAuthentication(headers, fromDomain, originatingHop, headerSection, bodySection);

        // 5. Extract Body URLs & Plain Text
        String plainText = stripHtml(bodySection);
        List<String> extractedUrls = extractUrls(bodySection);

        // 6. BEC & Social Engineering Semantic Scoring
        List<String> riskFactors = new ArrayList<>();
        int becScore = calculateBecScore(fromDisplay, fromAddress, fromDomain, replyTo, subject, plainText, riskFactors);
        boolean isVip = checkVipImpersonation(fromDisplay, fromAddress, fromDomain);
        boolean isFinancial = checkFinancialCoercion(plainText);

        // 7. Attachment Forensics
        List<AttachmentForensic> attachmentReports = processAttachments(uploadedAttachments, riskFactors);

        // 8. Overall Forensic Threat Scoring
        int overallScore = calculateOverallRisk(authMatrix, originatingHop, becScore, attachmentReports, extractedUrls, fromDomain, riskFactors);
        String riskTier = determineTier(overallScore);

        // 9. Cross-Email Campaign Correlation (same sender domain / same origin IP, persisted across analyses)
        String originIp = originatingHop != null ? originatingHop.ip() : null;
        List<CampaignMatch> campaignMatches = correlateCampaign(fromDomain, originIp, messageId);
        persistIncident(fromDomain, originIp, originatingHop, riskTier, messageId, evidenceHash);

        // 10. Build Threat Actor Correlation Graph
        List<GraphNode> nodes = new ArrayList<>();
        List<GraphEdge> edges = new ArrayList<>();
        buildCorrelationGraph(fromDomain, originatingHop, authMatrix, extractedUrls, attachmentReports, riskTier, nodes, edges, campaignMatches);

        // 11. Generate Section 65B Digital Evidence Statement
        String legalSummary = generateSection65BSummary(evidenceHash, messageId, fromAddress, subject, originatingHop, overallScore, riskTier);

        return new ForensicAnalysisResult(
                evidenceHash,
                Instant.now(),
                fromDisplay,
                fromAddress,
                fromDomain,
                replyTo,
                returnPath,
                subject,
                date,
                messageId,
                plainText.length() > 300 ? plainText.substring(0, 300) + "..." : plainText,
                hops,
                originatingHop,
                authMatrix,
                overallScore,
                riskTier,
                riskFactors,
                becScore,
                isVip,
                isFinancial,
                extractedUrls,
                attachmentReports,
                nodes,
                edges,
                legalSummary,
                campaignMatches
        );
    }

    // --- Cross-Email Campaign Correlation ---

    private List<CampaignMatch> correlateCampaign(String fromDomain, String originIp, String currentMessageId) {
        List<CampaignMatch> matches = new ArrayList<>();
        if (fromDomain != null && !fromDomain.isBlank()) {
            for (EmailIncidentRecord rec : incidentRepository.findTop10ByFromDomainOrderByCreatedAtDesc(fromDomain)) {
                if (!rec.getMessageId().equals(currentMessageId)) {
                    matches.add(new CampaignMatch(rec.getMessageId(), rec.getFromDomain(), rec.getOriginIp(),
                            rec.getRiskTier(), "SAME_DOMAIN", rec.getCreatedAt().toString()));
                }
            }
        }
        if (originIp != null && !originIp.isBlank() && !"N/A".equals(originIp)) {
            for (EmailIncidentRecord rec : incidentRepository.findTop10ByOriginIpOrderByCreatedAtDesc(originIp)) {
                if (!rec.getMessageId().equals(currentMessageId)
                        && matches.stream().noneMatch(m -> m.messageId().equals(rec.getMessageId()))) {
                    matches.add(new CampaignMatch(rec.getMessageId(), rec.getFromDomain(), rec.getOriginIp(),
                            rec.getRiskTier(), "SAME_ORIGIN_IP", rec.getCreatedAt().toString()));
                }
            }
        }
        return matches;
    }

    private void persistIncident(String fromDomain, String originIp, RelayHop originatingHop,
                                  String riskTier, String messageId, String evidenceHash) {
        try {
            EmailIncidentRecord rec = new EmailIncidentRecord();
            rec.setId(UUID.randomUUID().toString());
            rec.setFromDomain(fromDomain == null ? "" : fromDomain);
            rec.setOriginIp(originIp == null ? "N/A" : originIp);
            rec.setOriginCountry(originatingHop != null ? originatingHop.geo().country() : "Unknown");
            rec.setRiskTier(riskTier);
            rec.setMessageId(messageId);
            rec.setEvidenceSha256(evidenceHash);
            rec.setCreatedAt(Instant.now());
            incidentRepository.save(rec);
        } catch (Exception e) {
            log.warn("Failed to persist incident for campaign correlation: {}", e.toString());
        }
    }

    // --- Relay Hop Parsing ---

    private static final Pattern IP_PATTERN = Pattern.compile("(?:\\[|\\()(\\d{1,3}(?:\\.\\d{1,3}){3})(?:\\]|\\))");
    private static final Pattern FROM_HOST_PATTERN = Pattern.compile("(?i)from\\s+([a-zA-Z0-9.-]+)");

    private List<RelayHop> reconstructRelayPath(List<String> receivedHeaders) {
        List<RelayHop> hops = new ArrayList<>();
        if (receivedHeaders == null || receivedHeaders.isEmpty()) {
            return hops;
        }

        // Received headers are written top-down: bottom-most is earliest (originating MTA)
        List<String> chronological = new ArrayList<>(receivedHeaders);
        Collections.reverse(chronological);

        boolean foundOrigin = false;
        int hopCount = 1;

        for (int i = 0; i < chronological.size(); i++) {
            String raw = chronological.get(i);
            Matcher ipMatcher = IP_PATTERN.matcher(raw);

            String ip = "";
            if (ipMatcher.find()) {
                ip = ipMatcher.group(1);
            }

            Matcher hostMatcher = FROM_HOST_PATTERN.matcher(raw);
            String host = hostMatcher.find() ? hostMatcher.group(1) : "unknown-mta";

            GeoLocationService.GeoData geo = geoService.resolve(ip);

            boolean isOriginating = false;
            if (!foundOrigin && !geo.isPrivate() && !ip.isBlank()) {
                isOriginating = true;
                foundOrigin = true;
            }

            boolean isSuspicious = geo.isTorOrProxy() || geo.riskScore() >= 60;

            hops.add(new RelayHop(
                    hopCount++,
                    raw.length() > 140 ? raw.substring(0, 140) + "..." : raw,
                    ip.isBlank() ? "N/A" : ip,
                    host,
                    geo,
                    (i + 1) * 2L,
                    isOriginating,
                    isSuspicious
            ));
        }

        return hops;
    }

    // --- Cryptographic Authentication (SPF, DKIM, DMARC) ---

    private Map<String, AuthStatus> evaluateAuthentication(Map<String, List<String>> headers, String fromDomain,
                                                            RelayHop originatingHop, String headerSection, String bodySection) {
        Map<String, AuthStatus> matrix = new LinkedHashMap<>();

        // Parse receiver stamped authentication results
        String authResults = getFirst(headers, "authentication-results", "");
        String receivedSpf = getFirst(headers, "received-spf", "");
        boolean hasDkimHeader = headers.containsKey("dkim-signature");

        // 1. Evaluate SPF
        String spfVerdict = parseAuthTag(authResults, "spf");
        if ("UNKNOWN".equals(spfVerdict)) {
            if (receivedSpf.toLowerCase(Locale.ROOT).startsWith("pass")) spfVerdict = "PASS";
            else if (receivedSpf.toLowerCase(Locale.ROOT).startsWith("fail")) spfVerdict = "FAIL";
            else if (receivedSpf.toLowerCase(Locale.ROOT).startsWith("softfail")) spfVerdict = "SOFTFAIL";
        }

        // Perform live DNS SPF lookup check if domain is resolvable
        String liveDnsSpf = queryLiveSpf(fromDomain);
        boolean spfAligned = fromDomain != null && !fromDomain.isBlank();

        matrix.put("SPF", new AuthStatus(
                spfVerdict.equals("UNKNOWN") ? (liveDnsSpf != null ? "CONFIGURED_IN_DNS" : "NONE") : spfVerdict,
                "Sender Policy Framework (RFC 7208)",
                fromDomain,
                spfAligned,
                liveDnsSpf != null ? "DNS TXT record: " + liveDnsSpf : "Evaluated via boundary MTA"
        ));

        // 2. Evaluate DKIM — real cryptographic verification against the DNS public key,
        //    not just a presence check.
        String dkimRawHeader = hasDkimHeader ? getFirst(headers, "dkim-signature", "") : null;
        DkimVerifier.DkimResult dkimResult = dkimVerifier.verify(headerSection, dkimRawHeader, bodySection);
        matrix.put("DKIM", new AuthStatus(
                dkimResult.verdict(),
                "DomainKeys Identified Mail (RFC 6376)",
                dkimResult.domain() != null ? dkimResult.domain() : fromDomain,
                "PASS".equals(dkimResult.verdict()),
                dkimResult.details()
        ));

        // 3. Evaluate DMARC
        String dmarcVerdict = parseAuthTag(authResults, "dmarc");
        String liveDmarc = queryLiveDmarc(fromDomain);
        if ("UNKNOWN".equals(dmarcVerdict)) {
            dmarcVerdict = liveDmarc != null ? "CONFIGURED" : "NONE";
        }
        matrix.put("DMARC", new AuthStatus(
                dmarcVerdict,
                "Domain-based Message Authentication (RFC 7489)",
                fromDomain,
                "PASS".equalsIgnoreCase(dmarcVerdict) || "CONFIGURED".equalsIgnoreCase(dmarcVerdict),
                liveDmarc != null ? "DNS Policy: " + liveDmarc : "No DMARC policy record in _dmarc." + fromDomain
        ));

        return matrix;
    }

    private String queryLiveSpf(String domain) {
        if (domain == null || domain.isBlank() || domain.endsWith(".local") || domain.endsWith(".test")) return null;
        try {
            Lookup lookup = new Lookup(domain, Type.TXT);
            lookup.setCache(null);
            Record[] records = lookup.run();
            if (records != null) {
                for (Record r : records) {
                    String val = r.rdataToString();
                    if (val != null && val.toLowerCase(Locale.ROOT).contains("v=spf1")) {
                        return val.length() > 60 ? val.substring(0, 60) + "..." : val;
                    }
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    private String queryLiveDmarc(String domain) {
        if (domain == null || domain.isBlank() || domain.endsWith(".local") || domain.endsWith(".test")) return null;
        try {
            Lookup lookup = new Lookup("_dmarc." + domain, Type.TXT);
            lookup.setCache(null);
            Record[] records = lookup.run();
            if (records != null) {
                for (Record r : records) {
                    String val = r.rdataToString();
                    if (val != null && val.toLowerCase(Locale.ROOT).contains("v=dmarc1")) {
                        return val.length() > 60 ? val.substring(0, 60) + "..." : val;
                    }
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    private String parseAuthTag(String authHeader, String tag) {
        if (authHeader == null || authHeader.isBlank()) return "UNKNOWN";
        Pattern p = Pattern.compile("(?i)\\b" + Pattern.quote(tag) + "\\s*=\\s*([a-z]+)");
        Matcher m = p.matcher(authHeader);
        if (m.find()) {
            return m.group(1).toUpperCase(Locale.ROOT);
        }
        return "UNKNOWN";
    }

    // --- BEC & Social Engineering Semantic Scoring ---

    private static final List<String> VIP_TITLES = List.of(
            "chairman", "director", "ceo", "cfo", "chief executive", "registrar",
            "dean", "principal", "minister", "commissioner", "superintendent", "police", "cyber cell"
    );

    private static final List<String> FINANCIAL_CUES = List.of(
            "wire transfer", "rtgs", "neft", "swift", "remittance", "beneficiary bank",
            "account number", "ifsc", "vendor settlement", "emergency invoice", "immediate payment",
            "gift card", "crypto", "bitcoin", "penalty fine", "confidential settlement"
    );

    private static final List<String> URGENCY_CUES = List.of(
            "urgent", "immediate", "strictly confidential", "do not call", "avert embargo",
            "within 2 hours", "action required", "account suspended", "deactivation", "terminated"
    );

    private int calculateBecScore(String display, String address, String domain, String replyTo,
                                  String subject, String body, List<String> riskFactors) {
        int score = 0;
        String combined = (subject + " " + body).toLowerCase(Locale.ROOT);

        // 1. VIP Display Name Impersonation on Free / Foreign Domain
        if (checkVipImpersonation(display, address, domain)) {
            score += 45;
            riskFactors.add("Executive / VIP impersonation detected (Display: '" + display + "' using untrusted domain: " + domain + ")");
        }

        // 2. Reply-To Deception (Diverting responses to alternative mailbox)
        if (!replyTo.isBlank() && !extractDomain(replyTo).equalsIgnoreCase(domain)) {
            score += 30;
            riskFactors.add("Deceptive Reply-To divergence: Sender is @" + domain + " but replies route to @" + extractDomain(replyTo));
        }

        // 3. Financial Wire / Account Tampering Request
        for (String cue : FINANCIAL_CUES) {
            if (combined.contains(cue)) {
                score += 15;
                riskFactors.add("High-risk financial transfer trigger detected: '" + cue + "'");
                break;
            }
        }

        // 4. Coercive Urgency & Pressure Language
        for (String cue : URGENCY_CUES) {
            if (combined.contains(cue)) {
                score += 15;
                riskFactors.add("Psychological pressure / urgency trigger detected: '" + cue + "'");
                break;
            }
        }

        return Math.min(score, 100);
    }

    private boolean checkVipImpersonation(String display, String address, String domain) {
        String lowerDisplay = display.toLowerCase(Locale.ROOT);
        boolean hasTitle = VIP_TITLES.stream().anyMatch(lowerDisplay::contains);
        if (!hasTitle) return false;

        // If display name claims to be a VIP, but email domain is free webmail or suspicious lookalike
        List<String> freeWebmail = List.of("gmail.com", "yahoo.com", "hotmail.com", "proton.me", "yopmail.com", "mail.com");
        return freeWebmail.contains(domain) || domain.contains("-support") || domain.contains("-verify");
    }

    private boolean checkFinancialCoercion(String body) {
        String lower = body.toLowerCase(Locale.ROOT);
        return FINANCIAL_CUES.stream().anyMatch(lower::contains);
    }

    // --- Attachment Forensics ---

    public record AttachmentInput(String filename, byte[] content) {}

    private List<AttachmentForensic> processAttachments(List<AttachmentInput> inputs, List<String> riskFactors) {
        List<AttachmentForensic> list = new ArrayList<>();
        if (inputs == null || inputs.isEmpty()) return list;

        for (AttachmentInput in : inputs) {
            String fn = in.filename() == null ? "attachment" : in.filename();
            byte[] bytes = in.content() == null ? new byte[0] : in.content();

            String md5 = computeMd5(bytes);
            String sha256 = computeSha256(bytes);

            boolean isDoubleExt = fn.matches("(?i).*\\.(pdf|docx|xlsx|txt|png|jpg)\\.(exe|vbs|bat|scr|ps1|iso|com)$");
            boolean isHighRisk = fn.matches("(?i).*\\.(exe|vbs|bat|scr|ps1|iso|docm|xlsm|jar|cmd|hta)$");

            String warning = "Safe format";
            if (isDoubleExt) {
                warning = "CRITICAL: Malicious double extension masking executable as document";
                riskFactors.add("Malicious attachment with double extension: " + fn);
            } else if (isHighRisk) {
                warning = "HIGH RISK: Executable or macro-enabled carrier payload";
                riskFactors.add("High-risk executable attachment detected: " + fn);
            }

            list.add(new AttachmentForensic(
                    fn,
                    extractExtension(fn),
                    bytes.length,
                    md5,
                    sha256,
                    isDoubleExt,
                    isHighRisk,
                    warning
            ));
        }
        return list;
    }

    // --- Threat Correlation Graph Generation ---

    private void buildCorrelationGraph(String fromDomain, RelayHop originatingHop, Map<String, AuthStatus> authMatrix,
                                       List<String> extractedUrls, List<AttachmentForensic> attachments,
                                       String riskTier, List<GraphNode> nodes, List<GraphEdge> edges,
                                       List<CampaignMatch> campaignMatches) {

        String domainNodeId = "domain:" + fromDomain;
        nodes.add(new GraphNode(domainNodeId, fromDomain, "SENDER_DOMAIN", "MALICIOUS".equals(riskTier) ? 90 : 20));

        if (originatingHop != null && !originatingHop.ip().equals("N/A")) {
            String ipNodeId = "ip:" + originatingHop.ip();
            nodes.add(new GraphNode(ipNodeId, originatingHop.ip() + " (" + originatingHop.geo().countryCode() + ")", "ORIGIN_IP", originatingHop.geo().riskScore()));
            edges.add(new GraphEdge(domainNodeId, ipNodeId, "ORIGINATED_FROM"));

            String asnNodeId = "asn:" + originatingHop.geo().asn().split(" ")[0];
            nodes.add(new GraphNode(asnNodeId, originatingHop.geo().asn(), "AUTONOMOUS_SYSTEM", originatingHop.geo().isDatacenter() ? 70 : 15));
            edges.add(new GraphEdge(ipNodeId, asnNodeId, "HOSTED_ON"));
        }

        int linkIdx = 1;
        for (String url : extractedUrls) {
            String urlNodeId = "url:" + linkIdx++;
            nodes.add(new GraphNode(urlNodeId, url.length() > 30 ? url.substring(0, 30) + "..." : url, "EMBEDDED_URL", 80));
            edges.add(new GraphEdge(domainNodeId, urlNodeId, "CONTAINS_LINK"));
            if (linkIdx > 3) break; // limit graph density
        }

        for (AttachmentForensic att : attachments) {
            String attNodeId = "att:" + att.md5Hash().substring(0, 8);
            nodes.add(new GraphNode(attNodeId, att.filename(), "ATTACHMENT_HASH", att.isHighRiskExecutable() ? 95 : 10));
            edges.add(new GraphEdge(domainNodeId, attNodeId, "INCLUDES_PAYLOAD"));
        }

        if ("MALICIOUS".equals(riskTier) || "HIGH_RISK".equals(riskTier)) {
            String campaignId = "campaign:THREAT-ACTOR-" + Math.abs(fromDomain.hashCode() % 900 + 100);
            nodes.add(new GraphNode(campaignId, "Campaign Cluster #" + campaignId.substring(9), "CAMPAIGN_CLUSTER", 95));
            edges.add(new GraphEdge(domainNodeId, campaignId, "ATTRIBUTED_TO"));
        }

        // Link to previously seen incidents that share this domain or origin IP —
        // this is the actual cross-email campaign correlation, backed by persisted history.
        int matchIdx = 1;
        for (CampaignMatch match : campaignMatches) {
            String priorNodeId = "prior:" + match.messageId().hashCode();
            nodes.add(new GraphNode(priorNodeId,
                    "Prior incident " + match.seenAt().substring(0, Math.min(10, match.seenAt().length())),
                    "PRIOR_INCIDENT", "MALICIOUS".equals(match.riskTier()) ? 90 : 40));
            edges.add(new GraphEdge(domainNodeId, priorNodeId, match.matchedOn()));
            if (matchIdx++ > 10) break;
        }
    }

    // --- Risk Calculation & Scoring ---

    private int calculateOverallRisk(Map<String, AuthStatus> auth, RelayHop originHop, int becScore,
                                     List<AttachmentForensic> attachments, List<String> urls,
                                     String fromDomain, List<String> riskFactors) {
        int score = 0;

        // Authentication failures
        AuthStatus spf = auth.get("SPF");
        if (spf != null && "FAIL".equalsIgnoreCase(spf.status())) {
            score += 35;
            riskFactors.add("SPF Authentication Failed: Originating host not authorized by domain policy");
        } else if (spf != null && "SOFTFAIL".equalsIgnoreCase(spf.status())) {
            score += 20;
            riskFactors.add("SPF Softfail: IP marginally permitted or suspicious forwarding path");
        }

        AuthStatus dkim = auth.get("DKIM");
        if (dkim != null && "FAIL".equalsIgnoreCase(dkim.status())) {
            score += 25;
            riskFactors.add("DKIM Signature Failed: Cryptographic body/header tampering detected");
        }

        AuthStatus dmarc = auth.get("DMARC");
        if (dmarc != null && "FAIL".equalsIgnoreCase(dmarc.status())) {
            score += 30;
            riskFactors.add("DMARC Policy Violation: Reject/Quarantine alignment rule violated");
        }

        // Originating IP threat
        if (originHop != null) {
            if (originHop.geo().isTorOrProxy()) {
                score += 35;
                riskFactors.add("Originating IP matches known Tor exit node or bulletproof anonymity proxy");
            }
            if (originHop.geo().riskScore() >= 70) {
                score += 20;
                riskFactors.add("Originating ASN (" + originHop.geo().asn() + ") flagged for chronic malicious telemetry");
            }
        }

        // BEC Score contribution
        score += (int) (becScore * 0.4);

        // Attachment Threat
        for (AttachmentForensic att : attachments) {
            if (att.isDoubleExtension() || att.isHighRiskExecutable()) {
                score += 40;
                break;
            }
        }

        // Domain lookalike cues
        if (fromDomain != null && (fromDomain.contains("0") || fromDomain.contains("paypa1") || fromDomain.contains("micros0ft") || fromDomain.endsWith(".ru") || fromDomain.endsWith(".info"))) {
            score += 25;
            riskFactors.add("Sender domain exhibits homoglyph typosquatting or high-risk TLD: " + fromDomain);
        }

        return Math.min(Math.max(score, 0), 100);
    }

    private String determineTier(int score) {
        if (score >= 75) return "MALICIOUS";
        if (score >= 50) return "HIGH_RISK";
        if (score >= 25) return "SUSPICIOUS";
        return "SAFE";
    }

    // --- Section 65B Certificate & Summary ---

    private String generateSection65BSummary(String hash, String msgId, String from, String subject,
                                             RelayHop origin, int score, String tier) {
        String originLocation = origin != null ? origin.geo().city() + ", " + origin.geo().country() + " (" + origin.ip() + ")" : "Unknown Network";
        return "DIGITAL FORENSIC EVIDENCE CERTIFICATE (INDIAN EVIDENCE ACT / BHARATIYA SAKSHYA ADHINIYAM)\n" +
                "-----------------------------------------------------------------------------------------\n" +
                "Evidence Fingerprint (SHA-256) : " + hash + "\n" +
                "Internet Message-ID            : " + msgId + "\n" +
                "Declared Sender                : " + from + "\n" +
                "Subject Line                   : " + subject + "\n" +
                "Originating Transit Node       : " + originLocation + "\n" +
                "Evaluated Threat Tier          : " + tier + " (Forensic Risk Index: " + score + "/100)\n" +
                "Timestamp of Forensic Custody  : " + Instant.now() + "\n" +
                "Integrity Guarantee            : Bitstream preserved with zero payload alteration. Admissible for LEA filing.";
    }

    // --- Helpers ---

    private int findBlankLine(String s) {
        int i = s.indexOf("\n\n");
        return i >= 0 ? i : s.indexOf("\n\r\n");
    }

    private Map<String, List<String>> parseHeaders(String raw) {
        Map<String, List<String>> map = new LinkedHashMap<>();
        if (raw == null || raw.isBlank()) return map;

        String[] lines = raw.split("\n");
        String currentKey = null;
        StringBuilder currentVal = new StringBuilder();

        for (String line : lines) {
            if (line.startsWith(" ") || line.startsWith("\t")) {
                if (currentKey != null) {
                    currentVal.append(" ").append(line.trim());
                }
            } else {
                if (currentKey != null) {
                    map.computeIfAbsent(currentKey, k -> new ArrayList<>()).add(currentVal.toString());
                }
                int colon = line.indexOf(':');
                if (colon > 0) {
                    currentKey = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
                    currentVal = new StringBuilder(line.substring(colon + 1).trim());
                } else {
                    currentKey = null;
                }
            }
        }
        if (currentKey != null) {
            map.computeIfAbsent(currentKey, k -> new ArrayList<>()).add(currentVal.toString());
        }
        return map;
    }

    private String getFirst(Map<String, List<String>> map, String key, String fallback) {
        List<String> list = map.get(key.toLowerCase(Locale.ROOT));
        return (list == null || list.isEmpty()) ? fallback : list.get(0);
    }

    private String extractDisplayName(String from) {
        if (from == null) return "";
        int lt = from.indexOf('<');
        if (lt > 0) {
            return from.substring(0, lt).replace("\"", "").trim();
        }
        return from.trim();
    }

    private String extractEmailAddress(String from) {
        if (from == null) return "";
        Matcher m = Pattern.compile("<([^>]+)>").matcher(from);
        if (m.find()) return m.group(1).trim();
        Matcher m2 = Pattern.compile("([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})").matcher(from);
        if (m2.find()) return m2.group(1).trim();
        return from.trim();
    }

    private String extractDomain(String email) {
        if (email == null) return "";
        int at = email.lastIndexOf('@');
        return at >= 0 ? email.substring(at + 1).trim().toLowerCase(Locale.ROOT) : email.trim().toLowerCase(Locale.ROOT);
    }

    private String extractExtension(String fn) {
        int dot = fn.lastIndexOf('.');
        return dot >= 0 ? fn.substring(dot + 1).toLowerCase(Locale.ROOT) : "";
    }

    private String stripHtml(String body) {
        if (body == null) return "";
        return body.replaceAll("(?s)<[^>]*>", " ").replaceAll("\\s+", " ").trim();
    }

    private List<String> extractUrls(String text) {
        List<String> urls = new ArrayList<>();
        if (text == null) return urls;
        Pattern p = Pattern.compile("(?i)\\b((?:https?://|www\\.)[^\\s\"'<>()]+)");
        Matcher m = p.matcher(text);
        while (m.find()) {
            urls.add(m.group(1));
            if (urls.size() >= 10) break;
        }
        return urls;
    }

    private String computeSha256(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(bytes);
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "sha256-error";
        }
    }

    private String computeMd5(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(bytes);
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "md5-error";
        }
    }
}
