package com.cybershield.app.ui;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Toast;

import androidx.fragment.app.FragmentActivity;

import com.cybershield.app.shield.OverlayService;
import com.cybershield.app.shield.ShieldPrefs;

/**
 * Friction gate for "continue anyway" on a Secure Me warning. The user must
 * confirm with their fingerprint / face / device PIN before the block is lifted,
 * so nobody can tap straight through a warning (and a child or someone borrowing
 * the phone can't either).
 */
public class ProceedGateActivity extends FragmentActivity {

    private static final long ALLOW_MS = 30L * 60 * 1000;   // stop warning about this site for 30 min
    private String host;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setFinishOnTouchOutside(false);
        host = getIntent() == null ? null : getIntent().getStringExtra(OverlayService.EX_HOST);

        if (!BiometricGate.available(this)) {
            // No screen lock set — fall back to letting them through (can't gate).
            dismissWarningAndFinish();
            return;
        }

        BiometricGate.prompt(this,
                "Continue to this site?",
                "Secure Me flagged it. Confirm to proceed anyway.",
                new BiometricGate.Result() {
                    @Override public void onUnlocked() { dismissWarningAndFinish(); }
                    @Override public void onFailedOrCancelled() {
                        Toast.makeText(ProceedGateActivity.this,
                                "Not confirmed — staying on the safe side.", Toast.LENGTH_SHORT).show();
                        finishAndRemoveTask();   // warning overlay stays up
                    }
                });
    }

    private void dismissWarningAndFinish() {
        new ShieldPrefs(this).allowHost(host, ALLOW_MS);
        stopService(new Intent(this, OverlayService.class));   // removes the warning overlay
        // own task (see manifest) + remove it, so Android returns to the browser, not to Secure Me
        finishAndRemoveTask();
    }
}
