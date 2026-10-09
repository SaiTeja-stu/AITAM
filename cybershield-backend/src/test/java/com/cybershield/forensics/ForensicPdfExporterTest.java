package com.cybershield.forensics;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.rendering.PDFRenderer;
import org.apache.pdfbox.text.PDFTextStripper;
import org.apache.pdfbox.text.TextPosition;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ForensicPdfExporterTest {
    static EmailForensicsService.ForensicAnalysisResult sample(String subject) {
        var auth = new EmailForensicsService.AuthStatus("UNKNOWN", "SPF", "example.test", false,
                "No trusted provider records supplied; header assertions need independent verification.");
        return new EmailForensicsService.ForensicAnalysisResult("ab".repeat(32),
                Instant.parse("2026-10-09T09:00:00Z"), "Example Sender", "sender@example.test", "example.test",
                "", "", subject, "Fri, 9 Oct 2026 09:00:00 +0000", "<sample@example.test>", "Sample only",
                List.of(), null, Map.of("SPF", auth), 40, "SUSPICIOUS",
                List.of("SAMPLE DATA - no real investigation or complaint is represented.",
                        "Urgent payment wording requires independent verification."), 20, false, true,
                List.of("https://example.test/invoice"), List.of(), List.of(), List.of(), "Unsigned summary", List.of());
    }

    @Test
    void producesReadableUnsignedReportWithoutFalseCertification() throws Exception {
        byte[] bytes = new ForensicPdfExporter().export(sample("SAMPLE - Payment verification request"));
        try (PDDocument doc = PDDocument.load(bytes)) {
            String text = new PDFTextStripper().getText(doc);
            assertThat(text).contains("CYBER INCIDENT EXAMINATION REPORT", "UNSIGNED", "Examiner Review",
                    "Case / complaint reference", "Evidence Handling", "ab".repeat(32));
            assertThat(text).doesNotContain("I certify that", "Certificate under Section", "Admissible for LEA");
            assertThat(doc.getSignatureDictionaries()).isEmpty();
            for (int page = 1; page <= doc.getNumberOfPages(); page++) {
                assertThat(text).contains("Page " + page + " of " + doc.getNumberOfPages());
            }
            Path preview = Path.of("build", "reports", "forensics-preview");
            Files.createDirectories(preview);
            Files.write(preview.resolve("forensic-report-sample.pdf"), bytes);
            PDFRenderer renderer = new PDFRenderer(doc);
            for (int page = 0; page < doc.getNumberOfPages(); page++) {
                ImageIO.write(renderer.renderImageWithDPI(page, 110), "PNG",
                        preview.resolve("page-" + (page + 1) + ".png").toFile());
            }
        }
    }

    @Test
    void preservesUnsupportedUnicodeAndControlsAsCodePointsWithoutCrashing() throws Exception {
        String hostileSubject = "Evidence\u00ad\u0081\u0000 తెలుగు 🔒 — end";
        try (PDDocument doc = PDDocument.load(new ForensicPdfExporter().export(sample(hostileSubject)))) {
            String text = new PDFTextStripper().getText(doc);
            assertThat(text).contains("[U+00AD]", "[U+0081]", "[U+0000]", "[U+1F512]", "[U+2014]");
        }
    }

    @Test
    void longEvidenceCellsPaginateInsidePageMargins() throws Exception {
        try (PDDocument doc = PDDocument.load(new ForensicPdfExporter().export(sample("TOKEN".repeat(4000))))) {
            assertThat(doc.getNumberOfPages()).isGreaterThan(4);
            PDFTextStripper bounds = new PDFTextStripper() {
                @Override
                protected void processTextPosition(TextPosition p) {
                    assertThat(p.getXDirAdj()).isGreaterThanOrEqualTo(55f);
                    assertThat(p.getXDirAdj() + p.getWidthDirAdj()).isLessThan(541f);
                    // The lowest permitted text is the page footer; oversized rows must never run off-page.
                    assertThat(p.getYDirAdj()).isBetween(20f, 812f);
                    super.processTextPosition(p);
                }
            };
            String text = bounds.getText(doc);
            assertThat(text).contains("Examiner Review and Acknowledgement");
        }
    }
}
