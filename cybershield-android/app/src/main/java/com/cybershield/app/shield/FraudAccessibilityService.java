package com.cybershield.app.shield;

import android.accessibilityservice.AccessibilityService;
import android.content.Intent;
import android.os.SystemClock;
import android.util.Log;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;

import com.cybershield.app.engine.LocalFraudEngine;
import com.cybershield.app.engine.LocalVerdict;
import com.cybershield.app.engine.UpiUri;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

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

    private long lastHandledAt = 0;
    private String lastSignature = "";

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

        CharSequence pkg = event.getPackageName();
        if (pkg == null || !PAYMENT_PACKAGES.contains(pkg.toString())) return;

        int t = event.getEventType();
        if (t != AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED
                && t != AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED) return;

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
