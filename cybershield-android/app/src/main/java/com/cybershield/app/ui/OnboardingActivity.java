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

        b.btnNotif.setOnClickListener(v ->
                startActivity(new Intent("android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS")));

        b.btnTestSms.setOnClickListener(v -> {
            com.cybershield.app.sms.SmsReceiver.scan(getApplicationContext(), "+919812345678",
                    "Dear customer, your SBI account KYC is pending. Verify your debit card and the OTP "
                            + "at http://sbi-kyc-verify.tk now or your account will be blocked today.");
            android.widget.Toast.makeText(this, "Scanning… watch for the alert", android.widget.Toast.LENGTH_SHORT).show();
        });
        b.btnTestEmail.setOnClickListener(v -> {
            String raw = "From: \"PayPal Service\" <security@paypa1-account-verify.tk>\n"
                    + "Reply-To: paypal.recovery.team@gmail.com\n"
                    + "Subject: Urgent: your account has been limited\n"
                    + "Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail\n\n"
                    + "Verify your identity now at http://paypa1-account-verify.tk/login or your account "
                    + "will be permanently suspended. Confirm your password and the OTP sent to your phone.";
            startActivity(VerdictActivity.intent(this, "EMAIL", raw, "test"));
        });

        SecureStore store = CyberShieldApp.get().api().store();
        b.swBiometric.setChecked(store.biometricLock());
        b.swBiometric.setOnCheckedChangeListener((v, checked) -> store.setBiometricLock(checked));

        com.cybershield.app.shield.ShieldPrefs shield = new com.cybershield.app.shield.ShieldPrefs(this);
        b.swWatchBrowsers.setChecked(shield.watchBrowsers());
        b.swStrict.setChecked(shield.strictMode());
        b.swWatchBrowsers.setOnCheckedChangeListener((v, checked) -> {
            shield.setWatchBrowsers(checked);
            if (!checked) b.swStrict.setChecked(false);
            b.swStrict.setEnabled(checked);
        });
        b.swStrict.setEnabled(shield.watchBrowsers());
        b.swStrict.setOnCheckedChangeListener((v, checked) -> shield.setStrictMode(checked));
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

        boolean notif = notificationAccessGranted(this);
        b.btnNotif.setText(notif ? "Email auto-scan is ON ✓" : "Open notification-access setting");
        b.btnNotif.setEnabled(!notif);
    }

    private static boolean notificationAccessGranted(Context ctx) {
        String flat = Settings.Secure.getString(ctx.getContentResolver(), "enabled_notification_listeners");
        if (TextUtils.isEmpty(flat)) return false;
        String pkg = ctx.getPackageName();
        for (String s : flat.split(":")) {
            if (s != null && s.startsWith(pkg + "/")) return true;
        }
        return false;
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
