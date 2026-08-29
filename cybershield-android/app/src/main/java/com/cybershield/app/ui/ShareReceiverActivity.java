package com.cybershield.app.ui;

import android.content.Intent;
import android.os.Bundle;

import androidx.appcompat.app.AppCompatActivity;

/**
 * Entry point when the user shares text into Cyber Shield from any app
 * (WhatsApp, Messages, a browser, a social app). Classifies it and hands off
 * to the verdict screen.
 */
public class ShareReceiverActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        String shared = null;
        Intent intent = getIntent();
        if (intent != null && Intent.ACTION_SEND.equals(intent.getAction())
                && "text/plain".equals(intent.getType())) {
            shared = intent.getStringExtra(Intent.EXTRA_TEXT);
        }

        if (shared == null || shared.trim().isEmpty()) {
            finish();
            return;
        }
        String text = shared.trim();

        String type;
        if (text.toLowerCase().startsWith("upi://")) {
            type = "QR";
        } else if (text.startsWith("http://") || text.startsWith("https://")) {
            type = "URL";
        } else if (looksLikeEmail(text)) {
            type = "EMAIL";
        } else {
            type = "SOCIAL";
        }

        VerdictActivity.start(this, type, text, "share-sheet");
        finish();
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
