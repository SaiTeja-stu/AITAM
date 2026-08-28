package com.cybershield.app.engine;

import android.content.Context;

import com.cybershield.app.data.AppDatabase;
import com.cybershield.app.data.BlockedIndicator;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * On-device fraud pre-check. Runs entirely offline against a synced blocklist
 * plus a small rule set, so the accessibility shield can act in milliseconds
 * without a network round-trip and without sending screen content anywhere.
 *
 * The server verdict (when reachable) always takes precedence and refines this.
 */
public class LocalFraudEngine {

    private static final List<String> OTP_WORDS = Arrays.asList(
            "otp", "one time password", "one-time password", "cvv", "card pin", "atm pin");
    private static final List<String> URGENCY = Arrays.asList(
            "urgent", "immediately", "account blocked", "will be suspended", "act now",
            "last warning", "verify now", "within 24");
    private static final List<String> RECEIVE_MONEY = Arrays.asList(
            "scan to receive", "scan this qr to receive", "approve to receive",
            "scan to get your refund", "accept the request to receive");
    private static final List<String> IMPERSONATION = Arrays.asList(
            "income tax", "cbi", "customs", "trai", "your bank", "kyc", "rbi", "police", "digital arrest");

    private final AppDatabase db;

    public LocalFraudEngine(Context ctx) {
        this.db = AppDatabase.get(ctx);
    }

    /** Check a decoded QR / UPI payload. */
    public LocalVerdict checkPayment(UpiUri upi, String rawPayload) {
        LocalVerdict v = new LocalVerdict();
        if (upi != null && upi.valid) {
            v.initiatesPayment = upi.initiatesDebit();

            String vpaHash = Hashing.hmac(upi.payeeVpa);
            if (db.blocklistDao().isBlocked(BlockedIndicator.TYPE_VPA, vpaHash)) {
                v.add("This UPI ID has been reported for fraud", 60);
            }
            if (upi.isCollectOrMandate()) {
                v.add("This pulls money FROM your account (collect/mandate) - decline unless you started it", 45);
            }
            if (upi.amount != null && upi.amount >= 2000 && upi.note != null) {
                String n = upi.note.toLowerCase(Locale.ROOT);
                if (n.contains("refund") || n.contains("verify") || n.contains("prize")
                        || n.contains("cashback") || n.contains("kyc")) {
                    v.add("Large pre-filled amount for a suspicious reason (\"" + upi.note + "\")", 24);
                }
            }
            if (upi.payeeName != null && upi.payeeVpa != null) {
                String user = upi.payeeVpa.contains("@")
                        ? upi.payeeVpa.substring(0, upi.payeeVpa.indexOf('@')) : upi.payeeVpa;
                if (!norm(user).contains(norm(firstWord(upi.payeeName)))
                        && !norm(upi.payeeName).contains(norm(user))) {
                    v.add("Payee name doesn't match the UPI ID", 20);
                }
            }
        }
        // If the QR is actually a URL, run the URL checks on it
        if (rawPayload != null && (rawPayload.startsWith("http://") || rawPayload.startsWith("https://"))) {
            mergeUrl(v, rawPayload);
        }
        v.finish();
        return v;
    }

    /** Check free text (SMS / message / social). */
    public LocalVerdict checkText(String text) {
        LocalVerdict v = new LocalVerdict();
        if (text == null) { v.finish(); return v; }
        String t = text.toLowerCase(Locale.ROOT);

        if (containsAny(t, RECEIVE_MONEY)) {
            v.add("\"Scan to receive money\" - scanning a QR never credits you, this is a scam", 55);
        }
        if (containsAny(t, OTP_WORDS) && (t.contains("share") || t.contains("send") || t.contains("tell"))) {
            v.add("Asks you to share an OTP / PIN / CVV - always fraud", 50);
        }
        if (containsAny(t, IMPERSONATION) && (t.contains("verify") || t.contains("pay")
                || t.contains("click") || t.contains("blocked"))) {
            v.add("Impersonates an official body with a demand or threat", 24);
        }
        if (containsAny(t, URGENCY)) {
            v.add("Pressure / urgency language", 12);
        }
        for (String url : Extract.urls(text)) {
            mergeUrl(v, url);
        }
        v.finish();
        return v;
    }

    public LocalVerdict checkUrl(String url) {
        LocalVerdict v = new LocalVerdict();
        mergeUrl(v, url);
        v.finish();
        return v;
    }

    private void mergeUrl(LocalVerdict v, String url) {
        String host = Extract.host(url);
        if (host == null) return;
        if (db.blocklistDao().isBlocked(BlockedIndicator.TYPE_DOMAIN, host)) {
            v.add("Known malicious site: " + host, 55);
        }
        if (url.startsWith("http://")) {
            v.add("Link has no HTTPS: " + host, 12);
        }
        if (host.matches("^\\d{1,3}(\\.\\d{1,3}){3}$")) {
            v.add("Link points to a bare IP address", 16);
        }
        if (url.contains("@") && url.indexOf("@") > url.indexOf("://") + 3) {
            v.add("Deceptive '@' in the link hides the real destination", 22);
        }
    }

    private static boolean containsAny(String hay, List<String> needles) {
        for (String n : needles) if (hay.contains(n)) return true;
        return false;
    }
    private static String norm(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
    }
    private static String firstWord(String s) {
        String[] p = s.trim().split("\\s+");
        return p.length > 0 ? p[0] : s;
    }
}
