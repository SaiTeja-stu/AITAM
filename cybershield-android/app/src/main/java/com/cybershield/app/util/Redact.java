package com.cybershield.app.util;

import java.util.regex.Pattern;

/** Strips PII and trims text before it is stored locally or logged. */
public final class Redact {

    private static final Pattern EMAIL = Pattern.compile("[\\w.+-]+@[\\w-]+\\.[\\w.-]+");
    private static final Pattern PHONE = Pattern.compile("(?<!\\d)(\\+?\\d[\\d\\-\\s]{7,13}\\d)(?!\\d)");
    private static final Pattern VPA = Pattern.compile("[\\w.-]{2,}@[a-zA-Z]{2,}");
    private static final Pattern CARD = Pattern.compile("(?<!\\d)(?:\\d[ -]?){13,19}(?!\\d)");

    private Redact() {}

    public static String snippet(String text) {
        if (text == null) return "";
        String t = text;
        t = CARD.matcher(t).replaceAll("[CARD]");
        t = EMAIL.matcher(t).replaceAll("[EMAIL]");
        t = VPA.matcher(t).replaceAll("[VPA]");
        t = PHONE.matcher(t).replaceAll("[PHONE]");
        t = t.replaceAll("[\\r\\n]+", " ").trim();
        return t.length() > 200 ? t.substring(0, 200) + "…" : t;
    }
}
