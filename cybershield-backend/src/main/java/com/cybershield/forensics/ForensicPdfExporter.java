package com.cybershield.forensics;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.springframework.stereotype.Service;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Renders the digital-evidence report as a formal, printable PDF: letterhead with the Secure Me
 * logo, numbered sections, ruled tables, an unsigned reviewer block, and
 * "Page x of y" footers. Serif type and thin rules follow the look of regulatory / journal documents.
 */
@Service
public class ForensicPdfExporter {

    private static final PDRectangle PAGE = PDRectangle.A4;
    private static final float ML = 56, MR = 56, MT = 54, MB = 62;
    private static final float CW = PAGE.getWidth() - ML - MR;

    private static final PDFont SERIF = PDType1Font.TIMES_ROMAN;
    private static final PDFont SERIF_B = PDType1Font.TIMES_BOLD;
    private static final PDFont SERIF_I = PDType1Font.TIMES_ITALIC;

    private static final Color INK = new Color(0x1a, 0x1a, 0x1a);
    private static final Color GREY = new Color(0x6b, 0x6b, 0x6b);
    private static final Color RULE = new Color(0xb8, 0xb8, 0xb8);
    private static final Color BRAND = new Color(0x0b, 0x6b, 0x4f);
    private static final Color ALERT = new Color(0xa1, 0x1d, 0x1d);

    private static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("dd MMMM yyyy, HH:mm 'UTC'").withZone(ZoneOffset.UTC);

    public byte[] export(EmailForensicsService.ForensicAnalysisResult r) {
        try (PDDocument doc = new PDDocument()) {
            Page p = new Page(doc, loadLogo(doc));
            String hash = r.evidenceSha256() == null ? "n/a" : r.evidenceSha256();
            String reportNo = "SM-FR-" + hash.substring(0, Math.min(10, hash.length())).toUpperCase();
            Instant when = r.analyzedAt() == null ? Instant.now() : r.analyzedAt();

            p.letterhead(reportNo, TS.format(when));
            p.title("CYBER INCIDENT EXAMINATION REPORT", "Email Evidence Analysis | Unsigned Technical Report");
            p.paragraph("Prepared by Secure Me for investigative review. This is an automated technical report, "
                    + "not a government-issued document, police complaint receipt or statutory certificate.");
            p.keyValues(List.of(
                    new String[]{"Case / complaint reference", "Not provided - complete during review"},
                    new String[]{"Examining organisation", "Secure Me automated analysis service"},
                    new String[]{"Report status", "UNSIGNED - reviewer verification required"}));

            // 1 ---------------------------------------------------------------
            p.section("1.", "Summary of Findings");
            boolean severe = "HIGH_RISK".equals(r.riskTier()) || "MALICIOUS".equals(r.riskTier());
            p.paragraph("The email identified below was examined for forged sender details, failed authentication, "
                    + "suspicious relay origin, malicious content and financial-coercion language. It was assessed as "
                    + tier(r.riskTier()) + " with a Forensic Risk Index of " + r.overallRiskScore() + " out of 100.");
            p.table(new String[]{"Indicator", "Finding"}, new float[]{0.42f, 0.58f}, List.of(
                    new String[]{"Overall assessment", tier(r.riskTier())},
                    new String[]{"Forensic Risk Index", r.overallRiskScore() + " / 100"},
                    new String[]{"Business-email-compromise score", String.valueOf(r.becScore())},
                    new String[]{"Executive / VIP impersonation", r.isVipImpersonation() ? "Detected" : "Not detected"},
                    new String[]{"Financial coercion language", r.hasFinancialCoercion() ? "Detected" : "Not detected"}),
                    severe ? 1 : -1);

            // 2 ---------------------------------------------------------------
            p.section("2.", "Evidence Identification");
            p.keyValues(List.of(
                    new String[]{"Evidence fingerprint (SHA-256)", r.evidenceSha256()},
                    new String[]{"Analysed at", TS.format(when)},
                    new String[]{"Internet Message-ID", r.messageId()},
                    new String[]{"Date header", r.date()},
                    new String[]{"Declared sender", nz(r.fromDisplay()) + " <" + nz(r.fromAddress()) + ">"},
                    new String[]{"Sender domain", r.fromDomain()},
                    new String[]{"Reply-To", blank(r.replyTo()) ? "(none)" : r.replyTo()},
                    new String[]{"Return-Path", blank(r.returnPath()) ? "(none)" : r.returnPath()},
                    new String[]{"Subject", r.subject()}));

            // 3 ---------------------------------------------------------------
            p.section("3.", "Sender Authentication (SPF, DKIM, DMARC)");
            List<String[]> auth = new ArrayList<>();
            if (r.authMatrix() != null) {
                for (var e : r.authMatrix().entrySet()) {
                    var a = e.getValue();
                    auth.add(new String[]{e.getKey(), nz(a.status()), nz(a.details())});
                }
            }
            if (auth.isEmpty()) p.paragraph("No authentication results were present in the message headers.");
            else p.table(new String[]{"Mechanism", "Result", "Details"}, new float[]{0.18f, 0.16f, 0.66f}, auth, -1);

            // 4 ---------------------------------------------------------------
            p.section("4.", "Transmission Path and Origin");
            if (r.relayHops() != null && !r.relayHops().isEmpty()) {
                List<String[]> hops = new ArrayList<>();
                for (var h : r.relayHops()) {
                    var g = h.geo();
                    String where;
                    if (g == null) {
                        where = "-";
                    } else if (g.isPrivate()) {
                        where = "Private network (RFC 1918 / LAN)";
                    } else if ("DEMO_FIXTURE".equals(g.lookupStatus())) {
                        where = nz(g.city()) + ", " + nz(g.country()) + " [Demo fixture]";
                    } else if (g.latitude() == null || g.longitude() == null || "UNAVAILABLE".equals(g.lookupStatus())) {
                        where = "Location unavailable";
                    } else {
                        where = nz(g.city()) + ", " + nz(g.country());
                    }
                    String net = g == null ? "-" : nz(g.asn()) + " " + nz(g.isp());
                    hops.add(new String[]{String.valueOf(h.hopNumber()), nz(h.ip()), where, net});
                }
                p.table(new String[]{"Hop", "IP address", "Location", "Network"},
                        new float[]{0.08f, 0.22f, 0.30f, 0.40f}, hops, -1);
            }
            if (r.originatingHop() != null && r.originatingHop().geo() != null) {
                var hop = r.originatingHop();
                var g = hop.geo();
                String flags = (g.isTorOrProxy() ? "Tor / anonymising proxy. " : "")
                        + (g.isDatacenter() ? "Datacentre hosting. " : "");
                String locDesc = (g.latitude() != null && g.longitude() != null)
                        ? "in " + nz(g.city()) + ", " + nz(g.country())
                        : "with geographic coordinates unavailable";
                String fixtureNote = "DEMO_FIXTURE".equals(g.lookupStatus())
                        ? "Resolved via bundled demo sample fixture. "
                        : "";
                p.paragraph("The earliest extracted relay IP is " + nz(hop.ip()) + ", with an approximate network location "
                        + locDesc + " (" + nz(g.asn()) + ", " + nz(g.isp()) + "). "
                        + fixtureNote
                        + (flags.isBlank() ? "No anonymisation flag was returned by the lookup." : "Indicators: " + flags.trim()));
            } else {
                p.paragraph("No public originating IP address could be reconstructed from the Received headers.");
            }
            p.paragraph("Relay headers may be forged outside a trusted mail-provider boundary. IP geolocation describes "
                    + "network infrastructure and does not establish the sender's identity or physical location.");

            // 5 ---------------------------------------------------------------
            p.section("5.", "Risk Indicators Identified");
            if (r.riskFactors() == null || r.riskFactors().isEmpty()) {
                p.paragraph("No risk indicators were identified.");
            } else {
                p.numbered(r.riskFactors());
            }
            if (r.extractedUrls() != null && !r.extractedUrls().isEmpty()) {
                p.paragraph("Links found in the message body:");
                p.bullets(r.extractedUrls());
            }

            // 6 ---------------------------------------------------------------
            p.section("6.", "Attachments");
            if (r.attachments() == null || r.attachments().isEmpty()) {
                p.paragraph("No separately supplied attachments were examined. Embedded MIME attachments are not "
                        + "automatically extracted by this analysis path; this does not establish their absence.");
            } else {
                List<String[]> att = new ArrayList<>();
                for (var a : r.attachments()) {
                    att.add(new String[]{nz(a.filename()), nz(a.sha256Hash()), nz(a.riskWarning())});
                }
                p.table(new String[]{"File", "SHA-256", "Assessment"}, new float[]{0.24f, 0.44f, 0.32f}, att, -1);
            }

            // 7 ---------------------------------------------------------------
            p.section("7.", "Campaign Correlation");
            List<EmailForensicsService.CampaignMatch> matches = r.campaignMatches();
            if (matches == null || matches.isEmpty()) {
                p.paragraph("No matching entries were returned from the available local case history. This is not an "
                        + "exhaustive search of external incident databases.");
            } else {
                List<String[]> rows = new ArrayList<>();
                for (var m : matches) {
                    rows.add(new String[]{nz(m.matchedOn()), nz(m.messageId()), nz(m.riskTier()), nz(m.seenAt())});
                }
                p.table(new String[]{"Matched on", "Message-ID", "Tier", "Seen"},
                        new float[]{0.20f, 0.44f, 0.16f, 0.20f}, rows, -1);
            }

            // 8 ---------------------------------------------------------------
            p.section("8.", "Method and Limitations");
            p.paragraph("The evidence fingerprint is a SHA-256 hash of the submitted message text encoded as UTF-8, "
                    + "before line-ending normalization. It is not a hash of an original file unless its bytes match "
                    + "that encoding. Findings come from automated analysis of message headers and "
                    + "content and from public IP-geolocation data. They are investigative leads and should be "
                    + "corroborated with the mail provider's own logs before any legal action.");
            p.paragraph("The risk index is a heuristic score, not a probability of guilt or malware confirmation. "
                    + "Header authentication assertions require validation against trusted provider records. "
                    + "A hash alone does not prove authorship, acquisition history or chain of custody. "
                    + "Characters unsupported by the report font are shown as [U+XXXX] to preserve their identity.");

            // 9 ---------------------------------------------------------------
            p.section("9.", "Evidence Handling and Recommended Follow-up");
            p.numbered(List.of("Preserve the original email file and attachments in read-only storage; record acquisition "
                            + "source, time, examiner and an independent file hash.",
                    "Record every evidence transfer and access in a separate chain-of-custody register.",
                    "Corroborate suspicious relay, authentication and payment details with authorised provider records.",
                    "Submit any complaint through the appropriate official channel. This report does not submit a complaint."));
            p.room(225);
            p.section("10.", "Examiner Review and Acknowledgement");
            p.paragraph("To be completed by the responsible reviewer after checking the source evidence and findings. "
                    + "No signature, digital signing operation, legal admissibility determination or statutory "
                    + "certification is supplied by the application.");
            p.signatures();

            p.finish(reportNo, hash);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.save(out);
            return out.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("Failed to render forensic PDF", e);
        }
    }

    // ------------------------------------------------------------------ helpers

    private static PDImageXObject loadLogo(PDDocument doc) {
        try (InputStream in = ForensicPdfExporter.class.getResourceAsStream("/branding/secureme-logo.png")) {
            if (in == null) return null;
            return PDImageXObject.createFromByteArray(doc, in.readAllBytes(), "logo");
        } catch (Exception e) {
            return null;
        }
    }

    private static String tier(String t) {
        return t == null ? "UNKNOWN" : t.replace('_', ' ');
    }

    private static boolean blank(String s) {
        return s == null || s.isBlank();
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }

    /** Preserve unsupported code points explicitly instead of silently losing forensic text. */
    static String clean(String s) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder(s.length());
        for (int c : s.codePoints().toArray()) {
            if (c == '\n' || c == '\r' || c == '\t') b.append(' ');
            else if (c >= 0x20 && c <= 0x7E) b.append((char) c);
            else b.append(String.format("[U+%04X]", c));
        }
        return b.toString();
    }

    // ------------------------------------------------------------------ page writer

    private static final class Page {
        private final PDDocument doc;
        private final PDImageXObject logo;
        private PDPage page;
        private PDPageContentStream cs;
        private float y;
        private final List<PDPage> pages = new ArrayList<>();

        Page(PDDocument doc, PDImageXObject logo) throws IOException {
            this.doc = doc;
            this.logo = logo;
            newPage(true);
        }

        private void newPage(boolean first) throws IOException {
            if (cs != null) cs.close();
            page = new PDPage(PAGE);
            doc.addPage(page);
            pages.add(page);
            cs = new PDPageContentStream(doc, page);
            y = PAGE.getHeight() - MT;
            if (!first) y -= 4;
        }

        private void room(float need) throws IOException {
            if (y - need < MB) newPage(false);
        }

        // ---- primitives
        private void text(String s, PDFont f, float size, float x, Color c) throws IOException {
            cs.beginText();
            cs.setFont(f, size);
            cs.setNonStrokingColor(c);
            cs.newLineAtOffset(x, y);
            cs.showText(clean(s));
            cs.endText();
        }

        private float width(String s, PDFont f, float size) throws IOException {
            return f.getStringWidth(clean(s)) / 1000f * size;
        }

        private void hline(float x1, float x2, float yy, float w, Color c) throws IOException {
            cs.setStrokingColor(c);
            cs.setLineWidth(w);
            cs.moveTo(x1, yy);
            cs.lineTo(x2, yy);
            cs.stroke();
        }

        private List<String> wrap(String text, PDFont f, float size, float maxW) throws IOException {
            List<String> lines = new ArrayList<>();
            for (String para : clean(text).split(" {2,}|\\n")) {
                StringBuilder cur = new StringBuilder();
                for (String word : para.trim().split(" ")) {
                    if (word.isEmpty()) continue;
                    while (width(word, f, size) > maxW) { // hard-break very long tokens (hashes, URLs)
                        int low = 1, high = word.length();
                        while (low < high) {
                            int mid = (low + high + 1) / 2;
                            if (width(word.substring(0, mid), f, size) <= maxW) low = mid;
                            else high = mid - 1;
                        }
                        int n = low;
                        if (cur.length() > 0) { lines.add(cur.toString()); cur.setLength(0); }
                        lines.add(word.substring(0, n));
                        word = word.substring(n);
                    }
                    String tryLine = cur.length() == 0 ? word : cur + " " + word;
                    if (width(tryLine, f, size) > maxW) {
                        lines.add(cur.toString());
                        cur = new StringBuilder(word);
                    } else {
                        cur = new StringBuilder(tryLine);
                    }
                }
                if (cur.length() > 0) lines.add(cur.toString());
            }
            if (lines.isEmpty()) lines.add("");
            return lines;
        }

        // ---- document parts
        void letterhead(String reportNo, String date) throws IOException {
            float top = y;
            float logoSize = 48;
            if (logo != null) cs.drawImage(logo, ML, top - logoSize + 6, logoSize, logoSize);
            float tx = ML + (logo != null ? logoSize + 12 : 0);
            y = top - 14;
            text("SECURE ME", SERIF_B, 20, tx, BRAND);
            y -= 15;
            text("Digital Evidence Examination", SERIF_I, 10, tx, GREY);
            y -= 12;
            text("Automated analysis service", SERIF, 9.5f, tx, GREY);

            String[][] right = {{"Ref.", reportNo}, {"Date", date}, {"Handling", "RESTRICTED / UNSIGNED"}};
            float ry = top - 10;
            for (String[] kv : right) {
                String line = kv[0] + ": " + kv[1];
                float w = width(line, SERIF, 9.5f);
                y = ry;
                text(line, SERIF, 9.5f, PAGE.getWidth() - MR - w, INK);
                ry -= 12;
            }
            y = top - logoSize - 8;
            hline(ML, PAGE.getWidth() - MR, y, 1.2f, BRAND);
            y -= 26;
        }

        void title(String title, String sub) throws IOException {
            float w = width(title, SERIF_B, 15);
            text(title, SERIF_B, 15, (PAGE.getWidth() - w) / 2, INK);
            y -= 17;
            float sw = width(sub, SERIF, 10.5f);
            float sx = (PAGE.getWidth() - sw) / 2;
            text(sub, SERIF, 10.5f, sx, INK);
            hline(sx, sx + sw, y - 2, 0.6f, INK);
            y -= 26;
        }

        void section(String no, String title) throws IOException {
            room(80);
            y -= 6;
            text(no + "  " + title, SERIF_B, 11.5f, ML, INK);
            y -= 4;
            hline(ML, PAGE.getWidth() - MR, y, 0.5f, RULE);
            y -= 15;
        }

        void paragraph(String s) throws IOException {
            for (String line : wrap(s, SERIF, 10.5f, CW)) {
                room(15);
                text(line, SERIF, 10.5f, ML, INK);
                y -= 14;
            }
            y -= 4;
        }

        void bullets(List<String> items) throws IOException {
            for (String it : items) listItem("-", it);
            y -= 4;
        }

        void numbered(List<String> items) throws IOException {
            int i = 1;
            for (String it : items) listItem(i++ + ".", it);
            y -= 4;
        }

        private void listItem(String marker, String s) throws IOException {
            float indent = 20;
            boolean first = true;
            for (String line : wrap(s, SERIF, 10.5f, CW - indent)) {
                room(15);
                if (first) text(marker, SERIF, 10.5f, ML + 4, INK);
                text(line, SERIF, 10.5f, ML + indent, INK);
                y -= 14;
                first = false;
            }
        }

        /** Every cell, including labels and long evidence identifiers, wraps within its column. */
        void keyValues(List<String[]> rows) throws IOException {
            table(new String[]{"Field", "Recorded value"}, new float[]{0.30f, 0.70f}, rows, -1);
        }

        private void tableHeader(String[] head, float[] widths, float[] positions) throws IOException {
            room(44);
            hline(ML, PAGE.getWidth() - MR, y + 10, 1f, INK);
            int lines = 1;
            for (int i = 0; i < head.length; i++) {
                List<String> wrapped = wrap(head[i], SERIF_B, 10, widths[i] - 8);
                lines = Math.max(lines, wrapped.size());
                float yy = y;
                for (String line : wrapped) {
                    text(line, SERIF_B, 10, positions[i], INK);
                    y -= 12;
                }
                y = yy;
            }
            y -= lines * 12;
            hline(ML, PAGE.getWidth() - MR, y + 5, 0.6f, INK);
            y -= 9;
        }

        /** Split oversized rows across pages and repeat column headings on every continuation. */
        void table(String[] head, float[] frac, List<String[]> rows, int highlightRow) throws IOException {
            float[] widths = new float[frac.length], positions = new float[frac.length];
            float acc = ML;
            for (int i = 0; i < frac.length; i++) {
                widths[i] = CW * frac[i];
                positions[i] = acc + 4;
                acc += widths[i];
            }
            tableHeader(head, widths, positions);
            int rowNo = 0;
            for (String[] row : rows) {
                List<List<String>> cells = new ArrayList<>();
                int maxLines = 1;
                for (int i = 0; i < head.length; i++) {
                    List<String> lines = wrap(i < row.length ? row[i] : "", SERIF, 9.5f, widths[i] - 8);
                    cells.add(lines);
                    maxLines = Math.max(maxLines, lines.size());
                }
                float rowHeight = maxLines * 12 + 8;
                if (rowHeight < PAGE.getHeight() - MT - MB - 55 && y - rowHeight < MB) {
                    newPage(false);
                    tableHeader(head, widths, positions);
                }
                for (int line = 0; line < maxLines; line++) {
                    if (y - 18 < MB) {
                        newPage(false);
                        tableHeader(head, widths, positions);
                    }
                    for (int col = 0; col < head.length; col++) {
                        if (line < cells.get(col).size()) {
                            boolean hot = rowNo == highlightRow && col == 1;
                            text(cells.get(col).get(line), hot ? SERIF_B : SERIF, 9.5f,
                                    positions[col], hot ? ALERT : INK);
                        }
                    }
                    y -= 12;
                }
                y -= 4;
                hline(ML, PAGE.getWidth() - MR, y + 7, 0.3f, RULE);
                rowNo++;
            }
            hline(ML, PAGE.getWidth() - MR, y + 7, 1f, INK);
            y -= 12;
        }
        void signatures() throws IOException {
            room(140);
            y -= 10;
            float half = CW / 2 - 12;
            String[] cols = {"Reviewed by (name and role)", "Evidence custodian"};
            float startY = y;
            for (int c = 0; c < 2; c++) {
                float x = ML + c * (half + 24);
                y = startY;
                text(cols[c], SERIF_B, 10, x, INK);
                String[] labels = {"Name", "Designation", "Signature", "Date and place"};
                for (String lab : labels) {
                    y -= 24;
                    text(lab + ":", SERIF, 9.5f, x, GREY);
                    hline(x + width(lab + ":", SERIF, 9.5f) + 6, x + half, y - 2, 0.5f, INK);
                }
            }
            y -= 22;
        }

        /** Running header on continuation pages and "Page x of y" footers on all pages. */
        void finish(String reportNo, String hash) throws IOException {
            cs.close();
            int n = pages.size();
            for (int i = 0; i < n; i++) {
                try (PDPageContentStream c = new PDPageContentStream(doc, pages.get(i),
                        PDPageContentStream.AppendMode.APPEND, true, true)) {
                    if (i > 0) {
                        String head = "Secure Me  |  Digital Forensic Evidence Report  |  " + reportNo;
                        c.beginText();
                        c.setFont(SERIF_I, 8.5f);
                        c.setNonStrokingColor(GREY);
                        c.newLineAtOffset(ML, PAGE.getHeight() - 34);
                        c.showText(clean(head));
                        c.endText();
                        c.setStrokingColor(RULE);
                        c.setLineWidth(0.5f);
                        c.moveTo(ML, PAGE.getHeight() - 40);
                        c.lineTo(PAGE.getWidth() - MR, PAGE.getHeight() - 40);
                        c.stroke();
                    }
                    c.setStrokingColor(RULE);
                    c.setLineWidth(0.5f);
                    c.moveTo(ML, 46);
                    c.lineTo(PAGE.getWidth() - MR, 46);
                    c.stroke();
                    String left = "Secure Me  |  Confidential  |  Evidence SHA-256: "
                            + hash.substring(0, Math.min(16, hash.length())) + "...";
                    String right = "Page " + (i + 1) + " of " + n;
                    c.beginText();
                    c.setFont(SERIF, 8.5f);
                    c.setNonStrokingColor(GREY);
                    c.newLineAtOffset(ML, 34);
                    c.showText(clean(left));
                    c.endText();
                    float rw = SERIF.getStringWidth(right) / 1000f * 8.5f;
                    c.beginText();
                    c.setFont(SERIF, 8.5f);
                    c.setNonStrokingColor(GREY);
                    c.newLineAtOffset(PAGE.getWidth() - MR - rw, 34);
                    c.showText(right);
                    c.endText();
                }
            }
        }
    }
}
