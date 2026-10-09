package com.cybershield.forensics;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

/**
 * REST API for AI-Powered Email Threat Detection, Hop-by-Hop GeoLocation,
 * and Forensic Intelligence Platform (SIH26106).
 */
@RestController
@RequestMapping("/api/v1/forensics")
public class ForensicsController {

    private static final Logger log = LoggerFactory.getLogger(ForensicsController.class);

    private final EmailForensicsService forensicsService;
    private final ForensicPdfExporter pdfExporter;

    public ForensicsController(EmailForensicsService forensicsService, ForensicPdfExporter pdfExporter) {
        this.forensicsService = forensicsService;
        this.pdfExporter = pdfExporter;
    }

    public record RawAnalyzeRequest(String rawEml) {}

    public record IncidentReportRequest(
            String evidenceSha256,
            String subject,
            String sender,
            String riskTier,
            int riskScore,
            double userLat,
            double userLon,
            float accuracyMeters,
            String networkProvider,
            String reporterNotes
    ) {}

    /**
     * Analyze raw RFC 5322 text or pasted EML content.
     */
    @PostMapping(value = "/analyze-raw", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<EmailForensicsService.ForensicAnalysisResult> analyzeRaw(@RequestBody RawAnalyzeRequest request) {
        if (request == null || request.rawEml() == null || request.rawEml().isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        EmailForensicsService.ForensicAnalysisResult result = forensicsService.analyzeEmail(request.rawEml(), List.of());
        return ResponseEntity.ok(result);
    }

    /**
     * Analyze uploaded .eml or .msg file via multipart/form-data.
     */
    @PostMapping(value = "/analyze-eml", consumes = MediaType.MULTIPART_FORM_DATA_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<EmailForensicsService.ForensicAnalysisResult> analyzeEml(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "attachments", required = false) List<MultipartFile> attachments
    ) {
        try {
            if (file == null || file.isEmpty()) {
                return ResponseEntity.badRequest().build();
            }

            String content = new String(file.getBytes(), StandardCharsets.UTF_8);

            List<EmailForensicsService.AttachmentInput> attInputs = new ArrayList<>();
            if (attachments != null) {
                for (MultipartFile att : attachments) {
                    if (!att.isEmpty()) {
                        attInputs.add(new EmailForensicsService.AttachmentInput(att.getOriginalFilename(), att.getBytes()));
                    }
                }
            }

            EmailForensicsService.ForensicAnalysisResult result = forensicsService.analyzeEmail(content, attInputs);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Failed to parse uploaded EML", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Analyze raw EML and return an unsigned technical examination report as a PDF.
     */
    @PostMapping(value = "/export-pdf", consumes = MediaType.APPLICATION_JSON_VALUE, produces = "application/pdf")
    public ResponseEntity<byte[]> exportPdf(@RequestBody RawAnalyzeRequest request) {
        if (request == null || request.rawEml() == null || request.rawEml().isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        EmailForensicsService.ForensicAnalysisResult result = forensicsService.analyzeEmail(request.rawEml(), List.of());
        byte[] pdf = pdfExporter.export(result);
        return ResponseEntity.ok()
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header("X-Content-Type-Options", "nosniff")
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"forensic-evidence-"
                        + result.evidenceSha256().substring(0, 12) + ".pdf\"")
                .contentType(MediaType.valueOf("application/pdf"))
                .body(pdf);
    }

    /**
     * Retrieve pre-bundled demonstration catalog for live SIH presentation.
     */
    @GetMapping(value = "/samples", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<List<Map<String, String>>> listSamples() {
        return ResponseEntity.ok(SampleEmails.sampleCatalog());
    }

    /**
     * Retrieve specific sample email content.
     */
    @GetMapping(value = "/samples/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, String>> getSample(@PathVariable String id) {
        for (Map<String, String> s : SampleEmails.sampleCatalog()) {
            if (s.get("id").equalsIgnoreCase(id)) {
                return ResponseEntity.ok(s);
            }
        }
        return ResponseEntity.notFound().build();
    }

    /**
     * Prepare an incident reference. No external authority submission or storage is performed.
     */
    @PostMapping(value = "/incident-report", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> submitIncident(@RequestBody IncidentReportRequest req) {
        if (req == null || req.evidenceSha256() == null || !req.evidenceSha256().matches("[a-fA-F0-9]{64}")) {
            return ResponseEntity.badRequest().body(Map.of("message", "A valid SHA-256 evidence hash is required."));
        }
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("incidentId", "DRAFT-" + UUID.randomUUID());
        resp.put("status", "PREPARED_NOT_SUBMITTED");
        resp.put("evidenceSha256", req.evidenceSha256());
        resp.put("timestamp", Instant.now().toString());
        resp.put("jurisdictionStation", "Not assigned - submit through the official reporting channel");
        resp.put("submittedToAuthorities", false);
        resp.put("persisted", false);
        resp.put("message", "Draft reference only. No complaint was lodged or stored, and no police receipt was issued.");
        resp.put("helpline", "1930 / cybercrime.gov.in");
        return ResponseEntity.ok(resp);
    }
}
