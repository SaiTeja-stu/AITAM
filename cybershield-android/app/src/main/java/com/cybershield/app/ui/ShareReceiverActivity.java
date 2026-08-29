package com.cybershield.app.ui;

import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.google.mlkit.vision.common.InputImage;
import com.google.mlkit.vision.text.TextRecognition;
import com.google.mlkit.vision.text.latin.TextRecognizerOptions;

import java.io.InputStream;

/**
 * Entry point when the user shares content into Secure Me from any app.
 *
 * <p>Text (a DM, a post, a link) → analysed directly. An <b>image</b> (a
 * screenshot of a scam DM / post) → text is read on-device with ML Kit OCR and
 * then analysed. Nothing is uploaded and the image is never stored.
 */
public class ShareReceiverActivity extends AppCompatActivity {

    private static final String TAG = "CSShare";
    private static final int MAX_IMAGE_BYTES = 12 * 1024 * 1024;   // reject absurd images
    private static final int MAX_DECODE_PX = 2_500;                // downscale target (long edge)
    private static final int MAX_TEXT = 8_000;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Intent intent = getIntent();
        if (intent == null || !Intent.ACTION_SEND.equals(intent.getAction())) { finish(); return; }

        String mime = intent.getType() == null ? "" : intent.getType();

        if (mime.startsWith("image/")) {
            handleImage(intent);
            return;
        }

        String shared = intent.getStringExtra(Intent.EXTRA_TEXT);
        if (shared == null || shared.trim().isEmpty()) { finish(); return; }
        analyse(shared.trim());
        finish();
    }

    // ---- shared text ----------------------------------------------------

    private void analyse(String text) {
        String type;
        String lower = text.toLowerCase();
        if (lower.startsWith("upi://")) {
            type = "QR";
        } else if (lower.startsWith("http://") || lower.startsWith("https://")) {
            type = "URL";
        } else if (looksLikeEmail(text)) {
            type = "EMAIL";
        } else {
            type = "SOCIAL";
        }
        VerdictActivity.start(this, type, cap(text), "share-sheet");
    }

    // ---- shared image (screenshot OCR) --------------------------------

    private void handleImage(Intent intent) {
        Uri uri = intent.getParcelableExtra(Intent.EXTRA_STREAM);
        // Only accept a content:// URI the sharing app granted us read access to,
        // and only if the resolver confirms it is actually an image.
        String resolved = uri == null ? null : getContentResolver().getType(uri);
        if (uri == null
                || !"content".equalsIgnoreCase(uri.getScheme())
                || resolved == null || !resolved.startsWith("image/")) {
            Toast.makeText(this, "Couldn't read that image.", Toast.LENGTH_SHORT).show();
            finish();
            return;
        }

        Bitmap bmp;
        try {
            bmp = decodeCapped(uri);
        } catch (Exception e) {
            Log.w(TAG, "image decode failed", e);
            bmp = null;
        }
        if (bmp == null) {
            Toast.makeText(this, "That image couldn't be opened.", Toast.LENGTH_SHORT).show();
            finish();
            return;
        }

        Toast.makeText(this, "Reading the screenshot…", Toast.LENGTH_SHORT).show();
        final Bitmap toScan = bmp;
        try {
            TextRecognition.getClient(new TextRecognizerOptions.Builder().build())
                    .process(InputImage.fromBitmap(toScan, 0))
                    .addOnSuccessListener(result -> {
                        toScan.recycle();
                        String text = result.getText() == null ? "" : result.getText().trim();
                        if (text.isEmpty()) {
                            Toast.makeText(this, "No text found in that image.", Toast.LENGTH_SHORT).show();
                            finish();
                            return;
                        }
                        analyse(text);
                        finish();
                    })
                    .addOnFailureListener(e -> {
                        toScan.recycle();
                        Log.w(TAG, "OCR failed", e);
                        Toast.makeText(this, "Couldn't read the screenshot.", Toast.LENGTH_SHORT).show();
                        finish();
                    });
        } catch (Throwable t) {
            toScan.recycle();
            Log.w(TAG, "OCR init failed", t);
            finish();
        }
    }

    private Bitmap decodeCapped(Uri uri) throws Exception {
        // 1. size guard
        try (android.content.res.AssetFileDescriptor afd =
                     getContentResolver().openAssetFileDescriptor(uri, "r")) {
            long len = afd == null ? -1 : afd.getLength();
            if (len > MAX_IMAGE_BYTES) throw new SecurityException("image too large");
        } catch (Exception ignoredSizeCheck) { /* fall through — bounds still capped below */ }

        // 2. read bounds
        BitmapFactory.Options bounds = new BitmapFactory.Options();
        bounds.inJustDecodeBounds = true;
        try (InputStream in = getContentResolver().openInputStream(uri)) {
            BitmapFactory.decodeStream(in, null, bounds);
        }
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null;

        // 3. decode downscaled
        int longEdge = Math.max(bounds.outWidth, bounds.outHeight);
        int sample = 1;
        while (longEdge / sample > MAX_DECODE_PX) sample *= 2;
        BitmapFactory.Options opts = new BitmapFactory.Options();
        opts.inSampleSize = sample;
        opts.inPreferredConfig = Bitmap.Config.RGB_565;
        try (InputStream in = getContentResolver().openInputStream(uri)) {
            return BitmapFactory.decodeStream(in, null, opts);
        }
    }

    // ---- helpers -----------------------------------------------------

    private static String cap(String s) {
        return s.length() > MAX_TEXT ? s.substring(0, MAX_TEXT) : s;
    }

    /** Shared text that carries mail headers (forwarded email / "Show original"). */
    private static boolean looksLikeEmail(String text) {
        String head = text.length() > 4000 ? text.substring(0, 4000) : text;
        String lower = head.toLowerCase();
        int hits = 0;
        if (lower.matches("(?s).*(^|\\n)from:\\s?.*@.*")) hits++;
        if (lower.matches("(?s).*(^|\\n)subject:\\s?.*")) hits++;
        if (lower.contains("authentication-results:") || lower.matches("(?s).*(^|\\n)received:\\s?.*")) hits++;
        if (lower.matches("(?s).*(^|\\n)to:\\s?.*@.*")) hits++;
        return hits >= 2;
    }
}
