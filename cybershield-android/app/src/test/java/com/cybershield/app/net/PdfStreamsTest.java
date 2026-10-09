package com.cybershield.app.net;

import org.junit.Test;
import java.io.*;
import java.nio.charset.StandardCharsets;
import static org.junit.Assert.*;

public class PdfStreamsTest {
    @Test public void preservesPdfBytesAcrossBuffers() throws Exception {
        byte[] pdf = ("%PDF-1.4\n" + "sample evidence\n".repeat(2000) + "%%EOF").getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PdfStreams.copy(new ByteArrayInputStream(pdf), out);
        assertArrayEquals(pdf, out.toByteArray());
    }

    @Test public void rejectsErrorPagesAndEmptyResponses() throws Exception {
        for (String content : new String[]{"", "%PD", "<html>Service unavailable</html>", "{\"error\":\"failed\"}"}) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            assertThrows(IOException.class, () -> PdfStreams.copy(
                    new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)), out));
            assertEquals(0, out.size());
        }
    }

    @Test public void propagatesStorageFailure() {
        OutputStream broken = new OutputStream() {
            @Override public void write(int value) throws IOException { throw new IOException("Disk full"); }
        };
        assertThrows(IOException.class, () -> PdfStreams.copy(
                new ByteArrayInputStream("%PDF-1.4".getBytes(StandardCharsets.UTF_8)), broken));
    }
}
