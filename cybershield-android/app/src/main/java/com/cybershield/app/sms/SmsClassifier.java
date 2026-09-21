package com.cybershield.app.sms;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * TRAI / DLT-aware classifier for incoming SMS, from its text + sender.
 *
 * <p>Under TRAI regulations, bulk commercial, transactional, service and government SMS
 * must be sent through registered Principal Entities (PEs) with approved DLT headers
 * and content templates. Under recent 2025-2026 directions, category suffixes are also used:
 * <ul>
 *   <li><b>-T</b>: Transactional (account debit/credit, OTPs)</li>
 *   <li><b>-S</b>: Service (account updates, confirmations)</li>
 *   <li><b>-G</b>: Government communications</li>
 *   <li><b>-P</b>: Promotional / marketing</li>
 * </ul>
 *
 * <p>Legitimate OTPs, debit/credit alerts, and service notifications from verified
 * DLT headers never trigger scam/fraud warnings, even if they contain advisory urgency
 * words (e.g. "If not done by you, immediately report to bank").
 */
public final class SmsClassifier {

    public enum Category { OTP, TRANSACTIONAL, SERVICE, GOVERNMENT, PROMOTIONAL, PERSONAL, SPAM, FRAUD }

    private static final Pattern OTP_CODE = Pattern.compile("\\b\\d{4,8}\\b");

    /**
     * TRAI DLT header format:
     * - Optional 2-letter operator & circle prefix (e.g. "VM-", "VK-", "JD-", "AX-")
     * - Registered 3-9 alphanumeric Principal Entity code (e.g. "HDFCBK", "SBIINB", "PAYTMB")
     * - Optional TRAI message category suffix: "-T" (Txn), "-S" (Service), "-G" (Govt), "-P" (Promo)
     */
    private static final Pattern DLT_HEADER_PATTERN =
            Pattern.compile("(?i)^([a-z]{2}-)?([a-z0-9]{3,9})(-[tsgp])?$");

    private static final Pattern TEN_DIGIT = Pattern.compile("^\\+?\\d{10,13}$");

    /** Real registered DLT headers of common banks / services / govt entities. */
    private static final String[] KNOWN_HEADERS = {
            "hdfcbk", "hdfcbn", "sbiinb", "sbibnk", "sbiupi", "icicib", "icicbk", "axisbk", "axisbn",
            "kotakb", "kmbl", "yesbnk", "pnbsms", "cbssbi", "idfcfb", "bobibn", "canbnk", "unionb",
            "paytm", "phonpe", "gpay", "amazon", "amznin", "flpkrt", "myntra", "swiggy", "zomato",
            "irctc", "epfoho", "uidai", "cbdt", "mygov", "jio", "airtel", "vodaidea", "netflx",
            "incometax", "parivahan", "ceir"};

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

    private static final String[] SERVICE_WORDS = {
            "application", "approved", "ticket", "confirmed", "booked", "statement", "bill",
            "due date", "scheduled", "welcome to", "request received", "status"};

    private static final String[] PROMO_WORDS = {
            "offer", "sale", "% off", "discount", "buy now", "limited period", "coupon",
            "cashback", "recharge now", "unsubscribe", "t&c apply", "hurry", "flat rs"};

    private static final String[] SCAM_WORDS = {
            "you have won", "lottery", "lucky draw", "claim your prize", "kyc will be blocked",
            "account will be suspended", "update your pan", "click here to verify", "urgent action",
            "work from home", "earn daily", "loan approved", "get instant loan", "part time job",
            "apk", "install this app"};

    /** Pressure / action wording that a plain debit or credit alert does not contain. */
    private static final String[] PUSHY_WORDS = {
            "click", "verify", "update your", "kyc", "suspend", "blocked", "expire", "immediately",
            "link", "login", "log in", "claim", "refund", "reward", "install"};

    private static final String[] GAMBLING_WORDS = {
            "betting", "online bet", "satta", "matka", "teen patti", "teenpatti", "casino", "1xbet", "dafabet",
            "parimatch", "betway", "bet365", "mostbet", "ipl bet", "cricket bet", "color prediction", "colour prediction", "aviator"};

    private static final String[] GAMBLING_LURE = {
            "deposit", "bonus", "win ", "earn", "withdraw", "free", "guaranteed", "join", "register", "whatsapp", "telegram",
            "cashback", "100%", "rs.", "rs ", "inr", "₹"};

    private static final String[] HARD_OTP_THEFT = {
            "share the otp", "send the otp", "tell the otp", "forward this otp",
            "share your pin", "send your pin", "give your otp", "share otp with"};

    public static class DltHeaderInfo {
        public final boolean isDltShaped;
        public final String prefix;     // e.g. "VK" or null
        public final String entity;     // e.g. "hdfcbk"
        public final String typeSuffix; // "t", "s", "g", "p" or null
        public final boolean isKnownEntity;

        public DltHeaderInfo(boolean isDltShaped, String prefix, String entity, String typeSuffix, boolean isKnownEntity) {
            this.isDltShaped = isDltShaped;
            this.prefix = prefix;
            this.entity = entity;
            this.typeSuffix = typeSuffix;
            this.isKnownEntity = isKnownEntity;
        }
    }

    private SmsClassifier() {}

    /**
     * Parses the sender into TRAI DLT header components.
     */
    public static DltHeaderInfo parseDltHeader(String sender) {
        if (sender == null) return new DltHeaderInfo(false, null, null, null, false);
        String s = sender.trim().replace(" ", "");
        if (TEN_DIGIT.matcher(s).matches()) {
            return new DltHeaderInfo(false, null, null, null, false);
        }

        Matcher m = DLT_HEADER_PATTERN.matcher(s);
        if (!m.matches()) {
            return new DltHeaderInfo(false, null, null, null, false);
        }

        String prefix = m.group(1) != null ? m.group(1).replace("-", "").toUpperCase(Locale.ROOT) : null;
        String entity = m.group(2) != null ? m.group(2).toLowerCase(Locale.ROOT) : "";
        String suffix = m.group(3) != null ? m.group(3).replace("-", "").toLowerCase(Locale.ROOT) : null;

        boolean known = false;
        for (String k : KNOWN_HEADERS) {
            if (entity.equals(k)) {
                known = true;
                break;
            }
        }
        return new DltHeaderInfo(true, prefix, entity, suffix, known);
    }

    public static Category classify(String sender, String body, boolean engineFlaggedRisky, boolean engineFlaggedFraud) {
        String t = body == null ? "" : body.toLowerCase(Locale.ROOT);
        String s = sender == null ? "" : sender.trim();

        DltHeaderInfo dlt = parseDltHeader(s);
        boolean fromNumber = TEN_DIGIT.matcher(s.replace(" ", "")).matches();

        boolean hasLink = t.contains("http") || t.contains("www.") || t.contains("bit.ly") || t.contains(".apk");
        boolean pushy = containsAny(t, PUSHY_WORDS) || containsAny(t, SCAM_WORDS);

        // 1. HARD FRAUD CHECK: asking the user to share/send an OTP or PIN is ALWAYS fraud
        if (containsAny(t, HARD_OTP_THEFT)) {
            return Category.FRAUD;
        }

        // 1b. BETTING / GAMBLING PROMOTION: unsolicited real-money betting offers are never "safe"
        if (containsAny(t, GAMBLING_WORDS) && containsAny(t, GAMBLING_LURE)) {
            return Category.SPAM;
        }

        // A genuine OTP message delivers a code and warns "do not share it": it must never read as pushy
        boolean deliversOtp = containsAny(t, OTP_WORDS) && OTP_CODE.matcher(body == null ? "" : body).find() && !hasLink;

        // 2. SENDER-ID SPOOFING: a near-miss of a real bank header (e.g. HDFCBNK vs HDFCBK).
        // A near-miss header alone proves nothing (thousands of real headers exist), so it only
        // counts when the text also carries a link or pushy/scam wording. A plain debit/credit
        // alert never trips this.
        if (lookAlikeSenderHeader(s) && !deliversOtp && (hasLink || pushy)) {
            return Category.FRAUD;
        }

        // 3. INSTITUTION IMPERSONATION: reads like a bank/govt notice, comes from an ordinary
        // mobile number, AND pushes the reader to act. Personal chat like "paid to your account
        // via UPI" does not qualify.
        if (fromNumber && impersonatesInstitution(t) && (hasLink || pushy)) {
            return Category.FRAUD;
        }

        // 4. VERIFIED DLT SENDER CLASSIFICATION:
        // If message comes from a genuine DLT header (or has TRAI -T / -S / -G suffix),
        // protect it from false alarms caused by advisory bank urgency words (e.g. "immediately call bank").
        if (dlt.isDltShaped) {
            // OTP detection for DLT headers: OTPs sent under -T or banking headers
            if (containsAny(t, OTP_WORDS) && OTP_CODE.matcher(body == null ? "" : body).find()) {
                return Category.OTP;
            }

            // Check TRAI 2025-2026 category suffix
            if ("t".equals(dlt.typeSuffix)) {
                return Category.TRANSACTIONAL;
            }
            if ("s".equals(dlt.typeSuffix)) {
                return Category.SERVICE;
            }
            if ("g".equals(dlt.typeSuffix)) {
                return Category.GOVERNMENT;
            }
            if ("p".equals(dlt.typeSuffix)) {
                return Category.PROMOTIONAL;
            }

            // Known entity or transactional/service words
            if (containsAny(t, TXN_WORDS)) {
                return Category.TRANSACTIONAL;
            }
            if (containsAny(t, SERVICE_WORDS)) {
                return Category.SERVICE;
            }
            if (containsAny(t, PROMO_WORDS)) {
                return Category.PROMOTIONAL;
            }

            // If it's a known institutional header (SBI, HDFC, UIDAI, etc.) without hard scam words, keep safe
            if (dlt.isKnownEntity && !containsAny(t, SCAM_WORDS)) {
                return Category.TRANSACTIONAL;
            }
        }

        // 5. General OTP detection (non-DLT or unrecognized format)
        if (containsAny(t, OTP_WORDS) && OTP_CODE.matcher(body == null ? "" : body).find()) {
            return Category.OTP;
        }

        // 6. Direct scam / high-risk words for non-DLT or unverified senders
        if (containsAny(t, SCAM_WORDS) || engineFlaggedFraud) {
            return Category.FRAUD;
        }
        if (engineFlaggedRisky) {
            return Category.SPAM;
        }

        if (containsAny(t, PROMO_WORDS)) return Category.PROMOTIONAL;
        if (fromNumber && !containsAny(t, TXN_WORDS) && !containsAny(t, PROMO_WORDS)) return Category.PERSONAL;

        return dlt.isDltShaped ? Category.SERVICE : Category.PERSONAL;
    }

    /** Does the message claim to be from a bank / government / large service? */
    public static boolean impersonatesInstitution(String lowerBody) {
        int hits = 0;
        for (String w : INSTITUTION_WORDS) if (lowerBody.contains(w)) hits++;
        return hits >= 2;
    }

    /** Public so {@code SmsReceiver} can show the exact reason. */
    public static boolean looksLikeRegisteredSender(String sender) {
        DltHeaderInfo info = parseDltHeader(sender);
        return info.isDltShaped;
    }

    /**
     * True if the sender header is DLT-shaped and a near-miss (but not an exact
     * match) of a real bank/brand header — i.e. a spoofed / look-alike sender ID.
     */
    public static boolean lookAlikeSenderHeader(String sender) {
        if (sender == null) return false;
        DltHeaderInfo info = parseDltHeader(sender);
        if (!info.isDltShaped || info.entity == null) return false;

        String h = info.entity;
        if (h.length() < 5) return false;
        for (String real : KNOWN_HEADERS) {
            if (h.equals(real)) return false; // exact = legitimate, stop
            // a real brand with a letter or two added at either end (IPAYTM, PAYTMB, ATMHDFC) is a genuine variant
            if (real.length() >= 5 && h.contains(real)) return false;
            // same brand family (PAYTMB / PAYTM, ICICIT / ICICIB): a real variant, not a spoof
            if (real.length() <= 5 && h.startsWith(real)) return false;
        }
        for (String real : KNOWN_HEADERS) {
            if (real.length() < 5) continue;
            int d = editDistance(h, real, 1);
            if (d == 1 && Math.abs(h.length() - real.length()) <= 1) return true;
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
            case SERVICE -> "Service alert";
            case GOVERNMENT -> "Government communication";
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
