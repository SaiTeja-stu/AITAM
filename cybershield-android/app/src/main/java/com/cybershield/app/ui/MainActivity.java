package com.cybershield.app.ui;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;

import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.LinearLayoutManager;

import com.cybershield.app.CyberShieldApp;
import com.cybershield.app.R;
import com.cybershield.app.data.AuthRepository;
import com.cybershield.app.data.ScanEntity;
import com.cybershield.app.data.SecureStore;
import com.cybershield.app.databinding.ActivityMainBinding;

import java.util.List;
import java.util.concurrent.Executors;

import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

/** In-app dashboard: stats, quick checks, recent activity, education, protection. */
public class MainActivity extends AppCompatActivity {

    private ActivityMainBinding b;
    private SecureStore store;
    private RecentAdapter recentAdapter;
    private EduAdapter eduAdapter;
    private boolean unlocked = false;
    private boolean isAdmin = false;

    private final Handler main = new Handler(Looper.getMainLooper());

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

        recentAdapter = new RecentAdapter();
        b.recent.setLayoutManager(new LinearLayoutManager(this));
        b.recent.setAdapter(recentAdapter);

        eduAdapter = new EduAdapter(m -> startActivity(EduDetailActivity.intent(this, m)));
        b.education.setLayoutManager(new LinearLayoutManager(this));
        b.education.setAdapter(eduAdapter);

        b.btnScanQr.setOnClickListener(v -> {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
                    == PackageManager.PERMISSION_GRANTED) {
                startActivity(new Intent(this, ScanQrActivity.class));
            } else {
                cameraPerm.launch(Manifest.permission.CAMERA);
            }
        });

        b.btnAnalyze.setOnClickListener(v -> {
            String t = b.editText.getText() == null ? "" : b.editText.getText().toString().trim();
            if (t.isEmpty()) return;
            String type = t.toLowerCase().startsWith("upi://") ? "QR"
                    : (t.startsWith("http://") || t.startsWith("https://")) ? "URL" : "SMS";
            VerdictActivity.start(this, type, t, "dashboard");
            b.editText.setText("");
        });

        b.btnOverview.setOnClickListener(v -> startActivity(new Intent(this, OverviewActivity.class)));
        b.btnAllHistory.setOnClickListener(v -> startActivity(new Intent(this, HistoryActivity.class)));
        b.btnProtection.setOnClickListener(v -> startActivity(new Intent(this, OnboardingActivity.class)));

        b.btnSignOut.setOnClickListener(v -> signOut());
        b.btnLockSignOut.setOnClickListener(v -> signOut());
        b.btnUnlock.setOnClickListener(v -> promptUnlock());

        setupBottomNav();

        b.swBiometric.setChecked(store.biometricLock());
        b.swBiometric.setOnCheckedChangeListener((v, checked) -> {
            if (checked && !BiometricGate.available(this)) {
                b.swBiometric.setChecked(false);
                b.greeting.setText("Set up a fingerprint or screen lock first, then enable this.");
                return;
            }
            store.setBiometricLock(checked);
        });

        loadEducation();
    }

    @Override
    protected void onResume() {
        super.onResume();

        // Any session at all (access OR long-lived refresh token) is enough to proceed;
        // an expired access token is silently refreshed on the first API call.
        if (!store.hasSession()) {
            startActivity(new Intent(this, AuthActivity.class).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP));
            finish();
            return;
        }

        b.bottomNav.post(() -> b.bottomNav.setSelectedItemId(R.id.nav_home));

        if (store.biometricLock() && BiometricGate.available(this) && !unlocked) {
            showLock("Unlock with your fingerprint or screen lock.");
            promptUnlock();
        } else {
            unlocked = true;
            hideLock();
            ensureFreshSession();
            refreshRole();
        }

        refreshStats();
    }

    private void setupBottomNav() {
        b.bottomNav.setSelectedItemId(R.id.nav_home);
        b.bottomNav.setOnItemSelectedListener(item -> {
            int id = item.getItemId();
            if (id == R.id.nav_home) {
                b.scroll.smoothScrollTo(0, 0);
                return true;
            }
            if (id == R.id.nav_analyze) {
                startActivity(new Intent(this, AnalyzeConsoleActivity.class));
            } else if (id == R.id.nav_queue) {
                startActivity(new Intent(this, QueueActivity.class).putExtra("admin", isAdmin));
            } else if (id == R.id.nav_reports) {
                startActivity(new Intent(this, ReportsActivity.class));
            } else if (id == R.id.nav_learn) {
                startActivity(new Intent(this, EducationListActivity.class));
            }
            // keep Home as the res/selected tab; the launched screen is a push
            b.bottomNav.post(() -> b.bottomNav.setSelectedItemId(R.id.nav_home));
            return false;
        });
    }

    /** Ask the backend whether this account is an admin; hide the Reports tab otherwise. */
    private void refreshRole() {
        if (!store.hasAccount()) {           // offline / guest — no admin features
            isAdmin = false;
            android.view.MenuItem reports = b.bottomNav.getMenu().findItem(R.id.nav_reports);
            if (reports != null) reports.setVisible(false);
            b.btnOverview.setVisibility(View.GONE);
            return;
        }
        CyberShieldApp.get().api().api().me().enqueue(new Callback<>() {
            @Override public void onResponse(@androidx.annotation.NonNull Call<java.util.Map<String, Object>> call,
                                             @androidx.annotation.NonNull Response<java.util.Map<String, Object>> resp) {
                Object admin = resp.isSuccessful() && resp.body() != null ? resp.body().get("admin") : null;
                isAdmin = Boolean.TRUE.equals(admin);
                android.view.MenuItem reports = b.bottomNav.getMenu().findItem(R.id.nav_reports);
                if (reports != null) reports.setVisible(isAdmin);
                b.btnOverview.setVisibility(isAdmin ? View.VISIBLE : View.GONE);
            }
            @Override public void onFailure(@androidx.annotation.NonNull Call<java.util.Map<String, Object>> call,
                                            @androidx.annotation.NonNull Throwable t) { /* keep last known role */ }
        });
    }

    private void promptUnlock() {
        BiometricGate.prompt(this, new BiometricGate.Result() {
            @Override public void onUnlocked() {
                unlocked = true;
                hideLock();
                ensureFreshSession();   // mint a fresh access token for this session
                refreshRole();
                refreshStats();
            }
            @Override public void onFailedOrCancelled() {
                showLock("Couldn't verify. Try again, or sign out.");
            }
        });
    }

    /** If the short-lived access token is missing/expired, get a new one from the refresh token. */
    private void ensureFreshSession() {
        if (store.token() != null || !store.hasAccount()) { loadEducation(); return; }
        Executors.newSingleThreadExecutor().execute(() -> {
            String fresh = CyberShieldApp.get().api().tryRefresh();
            main.post(() -> {
                if (fresh == null && !store.hasSession()) {
                    startActivity(new Intent(this, AuthActivity.class).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP));
                    finish();
                } else {
                    loadEducation();
                }
            });
        });
    }

    private void showLock(String msg) {
        b.lockMsg.setText(msg);
        b.lockOverlay.setVisibility(View.VISIBLE);
    }

    private void hideLock() {
        b.lockOverlay.setVisibility(View.GONE);
    }

    private void signOut() {
        new AuthRepository().logout();
        unlocked = false;
        startActivity(new Intent(this, AuthActivity.class).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP));
        finish();
    }

    private void refreshStats() {
        Executors.newSingleThreadExecutor().execute(() -> {
            List<ScanEntity> rows;
            try {
                rows = CyberShieldApp.get().db().scanDao().recent();
            } catch (Exception e) {
                rows = java.util.Collections.emptyList();
            }
            int total = rows.size();
            int threats = 0;
            for (ScanEntity s : rows) {
                if ("MALICIOUS".equals(s.riskLevel) || "HIGH_RISK".equals(s.riskLevel)) threats++;
            }
            List<ScanEntity> recent = rows.subList(0, Math.min(6, rows.size()));
            final int ft = total, fth = threats;
            main.post(() -> {
                b.statChecks.setText(String.valueOf(ft));
                b.statThreats.setText(String.valueOf(fth));
                recentAdapter.set(recent);
                b.recentEmpty.setVisibility(recent.isEmpty() ? View.VISIBLE : View.GONE);
            });
        });
    }

    private void loadEducation() {
        eduAdapter.set(com.cybershield.app.data.EducationCatalog.bundled(this));   // offline-first
        CyberShieldApp.get().api().api().educationModules().enqueue(new Callback<>() {
            @Override
            public void onResponse(@androidx.annotation.NonNull Call<List<EduAdapter.Module>> call,
                                   @androidx.annotation.NonNull Response<List<EduAdapter.Module>> resp) {
                if (resp.isSuccessful() && resp.body() != null && !resp.body().isEmpty()) {
                    eduAdapter.set(resp.body());
                }
            }
            @Override
            public void onFailure(@androidx.annotation.NonNull Call<List<EduAdapter.Module>> call,
                                  @androidx.annotation.NonNull Throwable t) { /* bundled copy stays */ }
        });
    }
}
