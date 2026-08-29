package com.cybershield.app.shield;

import android.accessibilityservice.AccessibilityService;
import android.content.Intent;
import android.os.SystemClock;
import android.util.Log;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;

import com.cybershield.app.CyberShieldApp;
import com.cybershield.app.net.dto.AnalyzeResponse;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The web-browsing shield.
 *
 * <p>Scope is deliberately tight (privacy): it only acts inside browser apps,
 * reads only the address-bar URL and — for a suspected sign-in page — whether a
 * password field is present and which brand the page names. The risk decision
 * runs on-device; nothing is uploaded.
 *
 * <p>On a dangerous site it presses BACK and shows a full-screen warning
 * ({@link OverlayService}); in warn-only mode it shows the warning without
 * pressing BACK. Trusted (allowlisted) sites are never interrupted.
 */
public class FraudAccessibilityService extends AccessibilityService {

    private static final String TAG = "FraudShield";

    private ShieldPrefs prefs;
    private final ExecutorService io = Executors.newSingleThreadExecutor();

    private long lastUrlAt = 0;
    private String lastUrlChecked = "";

    @Override
    protected void onServiceConnected() {
        super.onServiceConnected();
        prefs = new ShieldPrefs(this);
        Log.i(TAG, "Browsing shield connected");
    }

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        if (event == null || prefs == null || !prefs.isEnabled()) return;

        CharSequence pkgCs = event.getPackageName();
        if (pkgCs == null) return;
        String pkg = pkgCs.toString();

        int t = event.getEventType();
        if (t != AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED
                && t != AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED) return;

        if (BrowserUrlReader.isBrowser(pkg) && prefs.watchBrowsers()) {
            handleBrowser(pkg);
        }
    }

    // ---- browser address-bar watching ----------------------------------

    private void handleBrowser(String pkg) {
        if (SystemClock.elapsedRealtime() - lastUrlAt < 700) return;

        AccessibilityNodeInfo root = getRootInActiveWindow();
        if (root == null) return;
        String url;
        BrowserPageReader.Page page;
        try {
            url = BrowserUrlReader.read(root, pkg);
            page = BrowserPageReader.read(root);
        } finally {
            root.recycle();
        }
        if (url == null || url.length() < 8) return;

        String host = hostOf(url);
        if (host == null) return;
        // re-check when the host changes OR the page turned into a login page
        String sig = host + "|" + (page.hasPasswordField || page.hasLoginText);
        if (sig.equals(lastUrlChecked)
                && SystemClock.elapsedRealtime() - lastUrlAt < 15000) return;
        lastUrlChecked = sig;
        lastUrlAt = SystemClock.elapsedRealtime();

        final String target = url;
        final String fHost = host;
        final BrowserPageReader.Page fPage = page;
        final boolean strict = prefs.strictMode();
        io.execute(() -> {
            try {
                AnalyzeResponse v = CyberShieldApp.get().analyzer().analyze("URL", target, null);

                if (v.trusted) return;   // on the verified safe list — never interrupt

                // Chrome-style client-side check: sign-in page for a brand it isn't.
                String impersonated = BrowserPageReader.impersonatedBrand(fPage, fHost);
                boolean pagePhish = impersonated != null && !v.trusted;

                Log.i(TAG, "browser " + fHost + " -> " + v.riskLevel + " " + v.riskScore
                        + " pw=" + fPage.hasPasswordField + " impersonates=" + impersonated + " strict=" + strict);

                boolean malicious = "MALICIOUS".equals(v.riskLevel) || pagePhish;
                boolean high = "HIGH_RISK".equals(v.riskLevel);
                boolean suspicious = "SUSPICIOUS".equals(v.riskLevel);
                boolean unverified = !v.trusted && !malicious && !high && !suspicious;

                if (malicious || high || (strict && (suspicious || unverified))) {
                    showBrowserOverlay(v, fHost, malicious || (strict && high), unverified, impersonated);
                    prefs.markAction();
                }
            } catch (Throwable ignored) {
                // the shield must never crash the foreground app
            }
        });
    }

    private void showBrowserOverlay(AnalyzeResponse v, String host, boolean hard, boolean unverified,
                                    String impersonatedBrand) {
        StringBuilder body = new StringBuilder();
        body.append(host).append("\n\n");
        if (impersonatedBrand != null) {
            body.append("This page is asking for your ").append(impersonatedBrand)
                    .append(" password, but it is NOT ").append(impersonatedBrand)
                    .append("'s website — it's ").append(host).append(".\n\n")
                    .append("Attackers build fake sign-in pages to steal your login. "
                            + "Do not type your password. Go back, and open ")
                    .append(impersonatedBrand).append(" by typing its address yourself.");
        } else if (unverified) {
            body.append("Secure Me could NOT confirm this site is safe. It's not on the "
                    + "verified list and we found no strong signals either way.\n\n"
                    + "If you didn't type this address yourself, go back. "
                    + "Never enter a password, OTP or card details on a site you reached from a link.");
        } else {
            int shown = 0;
            for (AnalyzeResponse.Signal s : v.signals) {
                if (s.weight <= 0) continue;
                body.append("• ").append(s.name).append('\n');
                if (++shown >= 4) break;
            }
            body.append("\nDon't enter passwords, OTPs or card details on this site. "
                    + "Open the real site yourself instead of following a link.");
        }

        Intent i = new Intent(this, OverlayService.class);
        i.putExtra(OverlayService.EX_TITLE, impersonatedBrand != null ? "Deceptive site ahead"
                : hard ? "Dangerous site - do not continue"
                : unverified ? "Unverified site - be careful" : "This site looks risky");
        i.putExtra(OverlayService.EX_BODY, body.toString());
        i.putExtra(OverlayService.EX_SCORE, v.riskScore);
        i.putExtra(OverlayService.EX_HARD, hard && !prefs.warnOnly());
        startForegroundService(i);

        if (hard && !prefs.warnOnly()) {
            performGlobalAction(GLOBAL_ACTION_BACK);
        }
    }

    private static String hostOf(String url) {
        try {
            android.net.Uri u = android.net.Uri.parse(url);
            String h = u.getHost();
            return h == null ? null : h.toLowerCase();
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public void onInterrupt() { }
}
