package com.cybershield.app.engine;

import android.net.Uri;

import java.util.Locale;

/** Parsed upi:// deep link (pay / collect / mandate). Defensive: never throws. */
public class UpiUri {

    public final boolean valid;
    public final String action;      // pay | collect | mandate | ""
    public final String payeeVpa;
    public final String payeeName;
    public final Double amount;
    public final String note;
    public final String currency;

    private UpiUri(boolean valid, String action, String pa, String pn, Double am, String tn, String cu) {
        this.valid = valid;
        this.action = action;
        this.payeeVpa = pa;
        this.payeeName = pn;
        this.amount = am;
        this.note = tn;
        this.currency = cu;
    }

    public static UpiUri parse(String raw) {
        if (raw == null) return empty();
        String s = raw.trim();
        if (!s.toLowerCase(Locale.ROOT).startsWith("upi://")) return empty();
        try {
            Uri u = Uri.parse(s);
            String action = u.getHost() == null ? "" : u.getHost().toLowerCase(Locale.ROOT);
            String pa = u.getQueryParameter("pa");
            String pn = u.getQueryParameter("pn");
            String tn = u.getQueryParameter("tn");
            String cu = u.getQueryParameter("cu");
            Double am = null;
            String amStr = u.getQueryParameter("am");
            if (amStr != null) {
                try { am = Double.parseDouble(amStr); } catch (NumberFormatException ignored) { }
            }
            boolean valid = pa != null && !pa.isEmpty();
            return new UpiUri(valid, action, pa, pn, am, tn, cu == null ? "INR" : cu);
        } catch (Exception e) {
            return empty();
        }
    }

    public boolean isCollectOrMandate() {
        return action.contains("collect") || action.contains("mandate");
    }

    /** Any scan-initiated UPI request debits the person who scans. */
    public boolean initiatesDebit() {
        return valid;
    }

    private static UpiUri empty() {
        return new UpiUri(false, "", null, null, null, null, "INR");
    }
}
