package com.cybershield.app.ui;

import android.os.Bundle;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.cybershield.app.databinding.ActivityAnalyzeConsoleBinding;

/** Pick a content type, paste content, get the full verdict on the next screen. */
public class AnalyzeConsoleActivity extends AppCompatActivity {

    private ActivityAnalyzeConsoleBinding b;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        b = ActivityAnalyzeConsoleBinding.inflate(getLayoutInflater());
        setContentView(b.getRoot());

        b.btnRun.setOnClickListener(v -> {
            String content = b.etContent.getText() == null ? "" : b.etContent.getText().toString().trim();
            if (content.isEmpty()) {
                Toast.makeText(this, "Paste something to check", Toast.LENGTH_SHORT).show();
                return;
            }
            VerdictActivity.start(this, selectedType(), content, "console");
        });
    }

    private String selectedType() {
        int id = b.typeGroup.getCheckedChipId();
        if (id == b.tEMAIL.getId()) return "EMAIL";
        if (id == b.tSMS.getId()) return "SMS";
        if (id == b.tQR.getId()) return "QR";
        if (id == b.tWEBPAGE.getId()) return "WEBPAGE";
        if (id == b.tSOCIAL.getId()) return "SOCIAL";
        return "URL";
    }
}
