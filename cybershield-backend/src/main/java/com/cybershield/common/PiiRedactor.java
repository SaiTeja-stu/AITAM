package com.cybershield.common;

import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

/**
 * Strips personal data from free text before it is logged or sent to any
 * external service such as an LLM (trust policy T-03). Detection patterns are
 * intentionally broad; false positives here are harmless.
 */
@Component
public class PiiRedactor {

    private static final Pattern EMAIL = Pattern.compile("[\\w.+-]+@[\\w-]+\\.[\\w.-]+");
    private static final Pattern PHONE = Pattern.compile("(?<!\\d)(\\+?\\d[\\d\\-\\s]{7,13}\\d)(?!\\d)");
    private static final Pattern UPI_VPA = Pattern.compile("[\\w.-]{2,}@[a-zA-Z]{2,}");
    private static final Pattern CARD = Pattern.compile("(?<!\\d)(?:\\d[ -]?){13,19}(?!\\d)");
    private static final Pattern AADHAAR = Pattern.compile("(?<!\\d)\\d{4}\\s?\\d{4}\\s?\\d{4}(?!\\d)");
    private static final Pattern CRLF = Pattern.compile("[\\r\\n]+");

    public String redact(String text) {
        if (text == null || text.isBlank()) return text;
        String t = text;
        t = CARD.matcher(t).replaceAll("[CARD]");
        t = AADHAAR.matcher(t).replaceAll("[ID]");
        t = EMAIL.matcher(t).replaceAll("[EMAIL]");
        t = UPI_VPA.matcher(t).replaceAll("[VPA]");
        t = PHONE.matcher(t).replaceAll("[PHONE]");
        return t;
    }

    /** Single-line, control-char-free version for safe logging (anti log-injection). */
    public String forLog(String text) {
        if (text == null) return "null";
        String r = redact(text);
        r = CRLF.matcher(r).replaceAll(" ");
        return r.length() > 300 ? r.substring(0, 300) + "…" : r;
    }
}
