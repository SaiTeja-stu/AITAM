package com.cybershield.app.ui;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Toast;

import androidx.fragment.app.FragmentActivity;

import com.cybershield.app.shield.OverlayService;

/**
 * Friction gate for "continue anyway" on a Secure Me warning. The user must
 * confirm with their fingerprint / face / device PIN before the block is lifted,
 * so nobody can tap straight through a warning (and a child or someone borrowing
 * the phone can't either).
 */
public class ProceedGateActivity extends FragmentActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setFinishOnTouchOutside(false);

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
                        finish();   // warning overlay stays up
                    }
                });
    }

    private void dismissWarningAndFinish() {
        stopService(new Intent(this, OverlayService.class));   // removes the warning overlay
        finish();
    }
}
