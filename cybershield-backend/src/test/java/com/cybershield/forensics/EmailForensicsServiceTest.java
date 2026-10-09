package com.cybershield.forensics;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class EmailForensicsServiceTest {
    @Test
    void hashCoversSubmittedTextBeforeNormalizationAndDoesNotInventHeaders() throws Exception {
        var repository = mock(EmailIncidentRepository.class);
        var service = new EmailForensicsService(mock(GeoLocationService.class), new DkimVerifier(), repository);
        String eml = "From: sender@example.test\r\nSubject: Sample\r\n\r\nSample body\r\n";
        var result = service.analyzeEmail(eml, List.of());
        assertThat(result.evidenceSha256()).isEqualTo(HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(eml.getBytes(StandardCharsets.UTF_8))));
        assertThat(result.evidenceSha256()).isNotEqualTo(service.analyzeEmail(eml.replace("\r\n", "\n"), List.of()).evidenceSha256());
        assertThat(result.date()).isEqualTo("Not present in submitted headers");
        assertThat(result.messageId()).isEqualTo("Not present in submitted headers");
        assertThat(result.section65bLegalSummary()).contains("UNSIGNED", "Not a government-issued report")
                .doesNotContain("Integrity Guarantee", "Admissible for LEA", "CERTIFICATE");
    }
}
