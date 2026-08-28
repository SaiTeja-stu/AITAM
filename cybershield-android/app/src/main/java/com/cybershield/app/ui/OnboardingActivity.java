package com.cybershield.app.ui;

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
import android.text.TextUtils;
import android.view.accessibility.AccessibilityManager;

import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import com.cybershield.app.CyberShieldApp;
import com.cybershield.app.data.SecureStore;
import com.cybershield.app.databinding.ActivityOnboardingBinding;
import com.cybershield.app.shield.FraudAccessibilityService;

/**
 * Walks the user through the special-access permissions the shield needs.
 * None of these can be granted with a normal dialog - each button deep-links
 * to the exact system settings screen.
 */
public class OnboardingActivity extends AppCompatActivity {

    private ActivityOnboardingBinding b;

    private final androidx.activity.result.ActivityResultLauncher<String[]> smsPerms =
            registerForActivityResult(new ActivityResultContracts.RequestMultiplePermissions(), r -> refresh());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        b = ActivityOnboardingBinding.inflate(getLayoutInflater());
        setContentView(b.getRoot());

        b.btnSms.setOnClickListener(v ->
                smsPerms.launch(new String[]{Manifest.permission.RECEIVE_SMS, Manifest.permission.READ_SMS}));

        b.btnOverlay.setOnClickListener(v -> startActivity(new Intent(
                Settings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:" + getPackageName()))));

        b.btnAccessibility.setOnClickListener(v ->
                startActivity(new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)));

        SecureStore store = CyberShieldApp.get().api().store();
        b.swBiometric.setChecked(store.biometricLock());
        b.swBiometric.setOnCheckedChangeListener((v, checked) -> store.setBiometricLock(checked));
    }

    @Override
    protected void onResume() {
        super.onResume();
        refresh();
    }

    private void refresh() {
        boolean sms = checkSelfPermission(Manifest.permission.RECEIVE_SMS)
                == android.content.pm.PackageManager.PERMISSION_GRANTED;
        boolean overlay = Settings.canDrawOverlays(this);
        boolean acc = isAccessibilityEnabled(this);

        b.btnSms.setText(sms ? "SMS access granted ✓" : "Grant SMS access");
        b.btnSms.setEnabled(!sms);
        b.btnOverlay.setText(overlay ? "Overlay allowed ✓" : "Open overlay setting");
        b.btnOverlay.setEnabled(!overlay);
        b.btnAccessibility.setText(acc ? "Shield service is ON ✓" : "Open accessibility setting");
    }

    public static boolean isAccessibilityEnabled(Context ctx) {
        AccessibilityManager am = (AccessibilityManager) ctx.getSystemService(Context.ACCESSIBILITY_SERVICE);
        if (am == null || !am.isEnabled()) return false;
        String flat = Settings.Secure.getString(ctx.getContentResolver(),
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
        if (TextUtils.isEmpty(flat)) return false;
        String target = ctx.getPackageName() + "/" + FraudAccessibilityService.class.getName();
        for (String s : flat.split(":")) {
            if (s.equalsIgnoreCase(target)) return true;
        }
        return false;
    }
}
