package com.cybershield.app.sms;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Truecaller-style bucket for an incoming SMS, from its text + sender.
 *
 * <p>This is a cheap first pass that decides how NOISY Secure Me should be:
 * a legitimate OTP or bank alert should never trigger a "scam" warning, while a
 * message the detection engine scored risky is surfaced loudly. The engine
 * verdict always wins for {@link Category#FRAUD}.
 */
public final class SmsClassifier {

    public enum Category { OTP, TRANSACTIONAL, PROMOTIONAL, PERSONAL, SPAM, FRAUD }

    private static final Pattern OTP_CODE = Pattern.compile("\\b\\d{4,8}\\b");
    /** India DLT header: 2-char operator prefix + '-' + registered 3-6 char principal-entity header. */
    private static final Pattern DLT_HEADER = Pattern.compile("(?i)^[a-z]{2}-[a-z0-9]{2,9}$"); // VM-HDFCBK, AD-SBIINB
    private static final Pattern TEN_DIGIT = Pattern.compile("^\\+?\\d{10,13}$");

    /** Real registered DLT headers of common banks / services (the part after the operator prefix). */
    private static final String[] KNOWN_HEADERS = {
            "hdfcbk", "hdfcbn", "sbiinb", "sbibnk", "sbiupi", "icicib", "icicbk", "axisbk", "axisbn",
            "kotakb", "kmbl", "yesbnk", "pnbsms", "cbssbi", "idfcfb", "bobibn", "canbnk", "unionb",
            "paytm", "phonpe", "gpay", "amazon", "amznin", "flpkrt", "myntra", "swiggy", "zomato",
            "irctc", "epfoho", "uidai", "cbdt", "mygov", "jio", "airtel", "vodaidea", "netflx"};

    private static final String[] INSTITUTION_WORDS = {
            "bank", "a/c", "acct", "account", "debit", "credit", "kyc", "netbanking", "net banking",
            "card", "upi", "aadhaar", "pan card", "income tax", "electricity", "gas connection",
            "sbi", "hdfc", "icici", "axis", "kotak", "paytm", "phonepe", "irctc", "epf", "gov"};

    private static final String[] OTP_WORDS = {
            "otp", "one time password", "one-time password", "verification code",
            "security code", "do not share", "never share this"};
    private static final String[] TXN_WORDS = {
            "credited", "debited", "a/c", "acct", "account", "balance", "txn", "transaction",
            "upi", "imps", "neft", "rs.", "inr", "avl bal", "spent on", "received in your"};
    private static final String[] PROMO_WORDS = {
            "offer", "sale", "% off", "discount", "buy now", "limited period", "coupon",
            "cashback", "recharge now", "unsubscribe", "t&c apply", "hurry"};
    private static final String[] SCAM_WORDS = {
            "you have won", "lottery", "lucky draw", "claim your prize", "kyc will be blocked",
            "account will be suspended", "update your pan", "click here to verify", "urgent action",
            "work from home", "earn daily", "loan approved", "get instant loan", "part time job"};

    private SmsClassifier() {}

    public static Category classify(String sender, String body, boolean engineFlaggedRisky, boolean engineFlaggedFraud) {
        String t = body == null ? "" : body.toLowerCase(Locale.ROOT);
        String s = sender == null ? "" : sender.trim();

        if (engineFlaggedFraud) return Category.FRAUD;

        boolean fromDltHeader = DLT_HEADER.matcher(s.replace(" ", "")).matches();
        boolean fromNumber = TEN_DIGIT.matcher(s.replace(" ", "")).matches();

        // SENDER-ID SPOOFING: the header is *shaped* like a DLT header and is a
        // near-miss of a real bank/brand header (HDFCBNK vs HDFCBK, AXISBNK vs AXISBK).
        if (lookAlikeSenderHeader(s)) return Category.FRAUD;

        // KEY CHECK: message reads like a bank / government notice, but it was sent
        // from an ordinary mobile number instead of a registered DLT sender ID.
        // Genuine institutional SMS in India can ONLY come from a registered header.
        if (impersonatesInstitution(t) && (fromNumber || (!fromDltHeader && !s.isEmpty()))) {
            boolean asks = t.contains("verify") || t.contains("click") || t.contains("update")
                    || t.contains("share") || t.contains("call") || t.contains("http")
                    || t.contains("otp") || t.contains("blocked") || t.contains("suspend");
            return asks ? Category.FRAUD : Category.SPAM;
        }

        if (containsAny(t, OTP_WORDS) && OTP_CODE.matcher(body == null ? "" : body).find()
                && !t.contains("share the otp") && !t.contains("send otp")) {
            return Category.OTP;
        }
        if (containsAny(t, SCAM_WORDS) || engineFlaggedRisky) {
            return engineFlaggedRisky ? Category.FRAUD : Category.SPAM;
        }
        if (fromDltHeader && containsAny(t, TXN_WORDS)) return Category.TRANSACTIONAL;
        if (containsAny(t, PROMO_WORDS)) return Category.PROMOTIONAL;
        if (fromNumber && !containsAny(t, TXN_WORDS) && !containsAny(t, PROMO_WORDS)) return Category.PERSONAL;
        return Category.TRANSACTIONAL;
    }

    /** Does the message claim to be from a bank / government / large service? */
    public static boolean impersonatesInstitution(String lowerBody) {
        int hits = 0;
        for (String w : INSTITUTION_WORDS) if (lowerBody.contains(w)) hits++;
        return hits >= 2;
    }

    /** Public so {@code SmsReceiver} can show the exact reason. */
    public static boolean looksLikeRegisteredSender(String sender) {
        return sender != null && DLT_HEADER.matcher(sender.trim().replace(" ", "")).matches();
    }

    /**
     * True if the sender header is DLT-shaped and a near-miss (but not an exact
     * match) of a real bank/brand header — i.e. a spoofed / look-alike sender ID.
     */
    public static boolean lookAlikeSenderHeader(String sender) {
        if (sender == null) return false;
        String s = sender.trim().replace(" ", "");
        if (!DLT_HEADER.matcher(s).matches()) return false;
        String h = s.substring(s.indexOf('-') + 1).toLowerCase(Locale.ROOT);
        for (String real : KNOWN_HEADERS) {
            if (h.equals(real)) return false;                 // exact = legitimate, stop
            int d = editDistance(h, real, 2);
            if (d >= 1 && d <= 2 && Math.abs(h.length() - real.length()) <= 2) return true;
        }
        return false;
    }

    private static int editDistance(String a, String b, int max) {
        int[] prev = new int[b.length() + 1];
        int[] cur = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); j++) prev[j] = j;
        for (int i = 1; i <= a.length(); i++) {
            cur[0] = i;
            int best = cur[0];
            for (int j = 1; j <= b.length(); j++) {
                int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                cur[j] = Math.min(Math.min(cur[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
                best = Math.min(best, cur[j]);
            }
            if (best > max) return max + 1;
            int[] tmp = prev; prev = cur; cur = tmp;
        }
        return prev[b.length()];
    }

    /** Should Secure Me raise a visible warning for this category? */
    public static boolean isAlertWorthy(Category c) {
        return c == Category.SPAM || c == Category.FRAUD;
    }

    public static String label(Category c) {
        return switch (c) {
            case OTP -> "One-time code";
            case TRANSACTIONAL -> "Bank / transaction alert";
            case PROMOTIONAL -> "Promotional";
            case PERSONAL -> "Personal";
            case SPAM -> "Spam";
            case FRAUD -> "Fraud / phishing";
        };
    }

    private static boolean containsAny(String hay, String[] needles) {
        for (String n : needles) if (hay.contains(n)) return true;
        return false;
    }
}
