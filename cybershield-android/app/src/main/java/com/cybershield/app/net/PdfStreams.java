package com.cybershield.app.net;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/** Bounded-memory copy; reject HTML/JSON error pages returned with HTTP 200. */
public final class PdfStreams {
    private PdfStreams() {}

    public static void copy(InputStream in, OutputStream out) throws IOException {
        byte[] signature = {'%', 'P', 'D', 'F', '-'};
        for (byte expected : signature) {
            if (in.read() != expected) throw new IOException("The server did not return a PDF report");
        }
        out.write(signature);
        byte[] buffer = new byte[8192];
        int count;
        while ((count = in.read(buffer)) != -1) out.write(buffer, 0, count);
        out.flush();
    }
}
