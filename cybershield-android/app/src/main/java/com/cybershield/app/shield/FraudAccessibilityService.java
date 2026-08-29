package com.cybershield.app.shield;

import android.accessibilityservice.AccessibilityService;
import android.content.Intent;
import android.os.SystemClock;
import android.util.Log;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;

import com.cybershield.app.CyberShieldApp;
import com.cybershield.app.engine.LocalFraudEngine;
import com.cybershield.app.engine.LocalVerdict;
import com.cybershield.app.engine.UpiUri;
import com.cybershield.app.net.dto.AnalyzeResponse;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The system-wide fraud shield.
 *
 * Scope is deliberately tight (privacy):
 *   - only fires for a fixed set of UPI / payment package names
 *   - only reads a screen when it looks like a payment confirmation
 *   - extracts just {payee, amount} via {@link PaymentScreenParser}
 *   - the risk decision runs on-device ({@link LocalFraudEngine}); nothing is uploaded
 *
 * On a blocking verdict it:
 *   1. presses BACK to leave the confirmation screen before the PIN pad, and
 *   2. shows a full-screen warning overlay ({@link OverlayService}).
 * In warn-only mode it shows the overlay without pressing BACK.
 *
 * FLAG_SECURE screens (bank PIN pads) cannot be read or covered - the shield
 * therefore acts on the confirmation screen that precedes them.
 */
public class FraudAccessibilityService extends AccessibilityService {

    private static final String TAG = "FraudShield";

    private static final Set<String> PAYMENT_PACKAGES = new HashSet<>(Arrays.asList(
            "com.google.android.apps.nbu.paisa.user", // Google Pay
            "com.phonepe.app",
            "net.one97.paytm",
            "in.org.npci.upiapp",                     // BHIM
            "com.axis.mobile",
            "com.sbi.lotusintouch",
            "com.snapwork.hdfc",
            "com.csam.icici.bank.imobile",
            "com.bankofbaroda.upi",
            "com.freecharge.android",
            "com.mobikwik_new"
    ));

    private LocalFraudEngine engine;
    private PaymentScreenParser parser;
    private ShieldPrefs prefs;
    private final ExecutorService io = Executors.newSingleThreadExecutor();

    private long lastHandledAt = 0;
    private String lastSignature = "";
    private long lastUrlAt = 0;
    private String lastUrlChecked = "";

    @Override
    protected void onServiceConnected() {
        super.onServiceConnected();
        engine = new LocalFraudEngine(this);
        parser = new PaymentScreenParser();
        prefs = new ShieldPrefs(this);
        Log.i(TAG, "Fraud shield connected");
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

        if (BrowserUrlReader.isBrowser(pkg)) {
            if (prefs.watchBrowsers()) handleBrowser(pkg);
            return;
        }
        if (!PAYMENT_PACKAGES.contains(pkg)) return;

        // debounce
        if (SystemClock.elapsedRealtime() - lastHandledAt < 800) return;

        AccessibilityNodeInfo root = getRootInActiveWindow();
        if (root == null) return;

        PaymentScreenParser.Result r;
        try {
            r = parser.parse(root);
        } finally {
            root.recycle();
        }
        if (!r.looksLikePaymentScreen || r.payeeVpa == null) return;

        String signature = r.payeeVpa + "|" + r.amount + "|" + r.looksLikeCollectRequest;
        if (signature.equals(lastSignature)
                && SystemClock.elapsedRealtime() - lastHandledAt < 8000) return;
        lastSignature = signature;
        lastHandledAt = SystemClock.elapsedRealtime();

        // Build a synthetic UPI object for the on-device engine
        UpiUri synthetic = UpiUri.parse(buildUpi(r));
        LocalVerdict verdict = engine.checkPayment(synthetic.valid ? synthetic : null, null);
        if (r.looksLikeCollectRequest) {
            verdict.add("This screen is a request to PULL money from you", 45);
            verdict.finish();
        }

        Log.i(TAG, "payment screen: score=" + verdict.score + " level=" + verdict.level);

        if (verdict.isBlocking()) {
            if (!prefs.warnOnly()) {
                performGlobalAction(GLOBAL_ACTION_BACK);
            }
            showOverlay(verdict, r);
            prefs.markAction();
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
            body.append("Cyber Shield could NOT confirm this site is safe. It's not on the "
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

    private String buildUpi(PaymentScreenParser.Result r) {
        StringBuilder sb = new StringBuilder("upi://");
        sb.append(r.looksLikeCollectRequest ? "collect" : "pay");
        sb.append("?pa=").append(r.payeeVpa);
        if (r.payeeName != null) sb.append("&pn=").append(android.net.Uri.encode(r.payeeName));
        if (r.amount != null) sb.append("&am=").append(r.amount);
        return sb.toString();
    }

    private void showOverlay(LocalVerdict v, PaymentScreenParser.Result r) {
        Intent i = new Intent(this, OverlayService.class);
        i.putExtra(OverlayService.EX_TITLE, v.level == LocalVerdict.Level.MALICIOUS
                ? "Do not pay — high fraud risk" : "Check before you pay");
        i.putExtra(OverlayService.EX_BODY, buildMessage(v, r));
        i.putExtra(OverlayService.EX_SCORE, v.score);
        i.putExtra(OverlayService.EX_HARD, v.level == LocalVerdict.Level.MALICIOUS && !prefs.warnOnly());
        startForegroundService(i);
    }

    private String buildMessage(LocalVerdict v, PaymentScreenParser.Result r) {
        StringBuilder sb = new StringBuilder();
        if (r.payeeVpa != null) sb.append("Payee: ").append(r.payeeVpa).append('\n');
        if (r.amount != null) sb.append("Amount: ₹").append(r.amount).append('\n');
        sb.append('\n');
        for (String reason : v.reasons) sb.append("• ").append(reason).append('\n');
        sb.append("\nScanning a QR or approving a UPI request only ever SENDS money. "
                + "If you were told to do this to receive money or a refund, it is a scam.");
        return sb.toString();
    }

    @Override
    public void onInterrupt() { }
}
