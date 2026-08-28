package com.cybershield.app.ui;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.view.View;

import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

import com.cybershield.app.CyberShieldApp;
import com.cybershield.app.data.AuthRepository;
import com.cybershield.app.data.SecureStore;
import com.cybershield.app.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

    private ActivityMainBinding b;
    private SecureStore store;
    private boolean unlocked = false;

    private final androidx.activity.result.ActivityResultLauncher<String> cameraPerm =
            registerForActivityResult(new ActivityResultContracts.RequestPermission(), granted -> {
                if (granted) startActivity(new Intent(this, ScanQrActivity.class));
            });

    private final androidx.activity.result.ActivityResultLauncher<String> notifPerm =
            registerForActivityResult(new ActivityResultContracts.RequestPermission(), g -> {});

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        store = CyberShieldApp.get().api().store();
        b = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(b.getRoot());

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
                && ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            notifPerm.launch(Manifest.permission.POST_NOTIFICATIONS);
        }

        b.btnScanQr.setOnClickListener(v -> {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
                    == PackageManager.PERMISSION_GRANTED) {
                startActivity(new Intent(this, ScanQrActivity.class));
            } else {
                cameraPerm.launch(Manifest.permission.CAMERA);
            }
        });

        b.btnCheckText.setOnClickListener(v -> {
            boolean showing = b.inputLayout.getVisibility() == View.VISIBLE;
            b.inputLayout.setVisibility(showing ? View.GONE : View.VISIBLE);
            b.btnAnalyze.setVisibility(showing ? View.GONE : View.VISIBLE);
        });

        b.btnAnalyze.setOnClickListener(v -> {
            String t = b.editText.getText() == null ? "" : b.editText.getText().toString().trim();
            if (t.isEmpty()) return;
            String type = t.startsWith("http://") || t.startsWith("https://") ? "URL" : "SMS";
            VerdictActivity.start(this, type, t, "manual");
        });

        b.btnHistory.setOnClickListener(v -> startActivity(new Intent(this, HistoryActivity.class)));
        b.btnProtection.setOnClickListener(v -> startActivity(new Intent(this, OnboardingActivity.class)));
        b.btnSignOut.setOnClickListener(v -> {
            new AuthRepository().logout();
            unlocked = false;
            goToAuth();
        });
    }

    @Override
    protected void onResume() {
        super.onResume();

        if (!store.hasToken()) {
            goToAuth();
            return;
        }
        if (unlocked || !store.biometricLock() || !BiometricGate.available(this)) {
            unlocked = true;
            revealContent();
            return;
        }
        // gate the UI behind a fingerprint / device credential
        b.content.setVisibility(View.INVISIBLE);
        BiometricGate.prompt(this, new BiometricGate.Result() {
            @Override public void onUnlocked() { unlocked = true; revealContent(); }
            @Override public void onFailedOrCancelled() { finish(); }
        });
    }

    private void revealContent() {
        b.content.setVisibility(View.VISIBLE);
    }

    private void goToAuth() {
        startActivity(new Intent(this, AuthActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP));
        finish();
    }
}
