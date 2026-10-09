package com.cybershield.forensics;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class ForensicsControllerTest {
    private final EmailForensicsService analyzer = mock(EmailForensicsService.class);
    private final ForensicPdfExporter exporter = new ForensicPdfExporter();
    private final ForensicsController controller = new ForensicsController(analyzer, exporter);

    @Test
    void emptyEvidenceIsRejectedWithoutStartingAnalysis() {
        assertThat(controller.exportPdf(new ForensicsController.RawAnalyzeRequest("  ")).getStatusCode().value()).isEqualTo(400);
        assertThat(controller.analyzeRaw(new ForensicsController.RawAnalyzeRequest(null)).getStatusCode().value()).isEqualTo(400);
        verifyNoInteractions(analyzer);
    }

    @Test
    void exportsAnActualPdfWithNoStoreHeaders() {
        when(analyzer.analyzeEmail(eq("email"), anyList())).thenReturn(ForensicPdfExporterTest.sample("Sample"));
        var response = controller.exportPdf(new ForensicsController.RawAnalyzeRequest("email"));
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getHeaders().getContentType().toString()).isEqualTo("application/pdf");
        assertThat(response.getHeaders().getFirst(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
        assertThat(response.getBody()).startsWith("%PDF-".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    @Test
    void incidentDraftNeverClaimsExternalSubmissionOrPersistence() {
        var request = new ForensicsController.IncidentReportRequest("ab".repeat(32), "Example", "sender@example.test",
                "SUSPICIOUS", 40, 0, 0, 0, "", "");
        var body = controller.submitIncident(request).getBody();
        assertThat(body).containsEntry("status", "PREPARED_NOT_SUBMITTED")
                .containsEntry("submittedToAuthorities", false).containsEntry("persisted", false);
        assertThat(body).doesNotContainKey("receiptToken");
    }
}
