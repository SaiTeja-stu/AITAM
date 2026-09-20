package com.cybershield.app.ui;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.widget.Toast;

import androidx.fragment.app.FragmentActivity;

import com.cybershield.app.data.Repository;
import com.cybershield.app.shield.OverlayService;
import com.cybershield.app.shield.ShieldPrefs;

/**
 * Friction gate for "continue anyway" on a Secure Me warning. The user must confirm with their fingerprint /
 * face / device PIN before the block is lifted, so nobody can tap straight through a warning (and a child or
 * someone borrowing the phone can't either).
 *
 * <p>On success: the site is allowed for 30 minutes, a dangerous-site block is reopened in the browser, and - for
 * high / very-high risk - the site address (no query string) and score are reported to the Secure Me dashboard.
 */
public class ProceedGateActivity extends FragmentActivity {

    private static final long ALLOW_MS = 30L * 60 * 1000;
    private static final int REPORT_MIN_SCORE = 50;

    private String host;
    private String url;
    private String pkg;
    private int score;
    private boolean reopen;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setFinishOnTouchOutside(false);
        Intent in = getIntent();
        host = in == null ? null : in.getStringExtra(OverlayService.EX_HOST);
        url = in == null ? null : in.getStringExtra(OverlayService.EX_URL);
        pkg = in == null ? null : in.getStringExtra(OverlayService.EX_PKG);
        score = in == null ? 0 : in.getIntExtra(OverlayService.EX_SCORE, 0);
        reopen = in != null && in.getBooleanExtra(OverlayService.EX_HARD, false);   // hard block replaced the page

        if (!BiometricGate.available(this)) {
            if (reopen) {
                // a dangerous site can only be opened with a screen lock to confirm against
                Toast.makeText(this, "Set a screen lock (PIN, pattern or fingerprint) to continue past a "
                        + "dangerous-site warning.", Toast.LENGTH_LONG).show();
                finishAndRemoveTask();
            } else {
                proceed();   // soft warning and nothing to confirm with: keep the old behaviour
            }
            return;
        }

        BiometricGate.prompt(this,
                "Continue to this site?",
                "Secure Me flagged it (risk " + score + "/100). Confirm to proceed anyway.",
                new BiometricGate.Result() {
                    @Override public void onUnlocked() { proceed(); }
                    @Override public void onFailedOrCancelled() {
                        Toast.makeText(ProceedGateActivity.this,
                                "Not confirmed - staying on the safe side.", Toast.LENGTH_SHORT).show();
                        finishAndRemoveTask();   // warning overlay stays up
                    }
                });
    }

    private void proceed() {
        new ShieldPrefs(this).allowHost(host, ALLOW_MS);
        stopService(new Intent(this, OverlayService.class));   // removes the warning overlay

        // tell the dashboard the user chose to go on (address without query string, plus the score)
        if (score >= REPORT_MIN_SCORE && url != null) {
            String note = "AUTO-REPORT: user continued past a Secure Me warning (risk " + score
                    + "/100) after confirming with fingerprint / PIN.";
            new Repository(getApplicationContext()).report("URL", stripQuery(url), note);
        }

        // a dangerous-site block replaced the page: open the site again, now that the user has agreed
        if (reopen && url != null) {
            try {
                Intent open = new Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                if (pkg != null && !pkg.isEmpty()) open.setPackage(pkg);
                startActivity(open);
            } catch (Exception ignored) {
            }
        }
        // own task (see manifest) + remove it, so Android returns to the browser, not to Secure Me
        finishAndRemoveTask();
    }

    private static String stripQuery(String u) {
        int q = u.indexOf('?');
        int h = u.indexOf('#');
        int cut = q < 0 ? h : (h < 0 ? q : Math.min(q, h));
        String s = cut < 0 ? u : u.substring(0, cut);
        return s.length() > 300 ? s.substring(0, 300) : s;
    }
}
