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
        } else {
            type = "SOCIAL";
        }

        VerdictActivity.start(this, type, text, "share-sheet");
        finish();
    }
}
