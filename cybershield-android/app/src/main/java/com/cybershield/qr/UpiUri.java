package com.cybershield.qr;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Parsed UPI deep link, e.g.
 *   upi://pay?pa=merchant@ybl&pn=Shop&am=500&tn=order&cu=INR
 *   upi://collect?pa=...   (pull request)
 *   upi://mandate?...      (recurring auto-debit)
 *
 * Parsing is defensive: malformed input yields an object with whatever could be
 * extracted and {@link #valid()} == false.
 */
public final class UpiUri {

    /** pay | collect | mandate | (unknown) */
    private final String action;
    private final Map<String, String> params;
    private final boolean valid;

    private UpiUri(String action, Map<String, String> params, boolean valid) {
        this.action = action;
        this.params = params;
        this.valid = valid;
    }

    public static UpiUri parse(String raw) {
        Map<String, String> params = new LinkedHashMap<>();
        if (raw == null) return new UpiUri("", params, false);
        String s = raw.trim();
        if (!s.toLowerCase().startsWith("upi://")) {
            return new UpiUri("", params, false);
        }
        String rest = s.substring("upi://".length());
        String action;
        String query;
        int q = rest.indexOf('?');
        if (q >= 0) {
            action = rest.substring(0, q).toLowerCase();
            query = rest.substring(q + 1);
        } else {
            action = rest.toLowerCase();
            query = "";
        }
        for (String pair : query.split("&")) {
            if (pair.trim().isEmpty()) continue;
            int eq = pair.indexOf('=');
            String k = eq >= 0 ? pair.substring(0, eq) : pair;
            String v = eq >= 0 ? pair.substring(eq + 1) : "";
            try {
                k = URLDecoder.decode(k, StandardCharsets.UTF_8).trim();
                v = URLDecoder.decode(v, StandardCharsets.UTF_8).trim();
            } catch (RuntimeException ignored) {
                // keep raw
            }
            if (!k.isEmpty()) params.putIfAbsent(k.toLowerCase(), v);
        }
        boolean valid = params.containsKey("pa"); // a payee address is mandatory for a real request
        return new UpiUri(action, params, valid);
    }

    public String action() { return action; }
    public boolean valid() { return valid; }
    public Map<String, String> params() { return params; }

    public Optional<String> payeeVpa() { return Optional.ofNullable(emptyToNull(params.get("pa"))); }
    public Optional<String> payeeName() { return Optional.ofNullable(emptyToNull(params.get("pn"))); }
    public Optional<String> note() { return Optional.ofNullable(emptyToNull(params.get("tn"))); }
    public Optional<String> merchantCode() { return Optional.ofNullable(emptyToNull(params.get("mc"))); }
    public Optional<String> currency() { return Optional.ofNullable(emptyToNull(params.get("cu"))); }

    public Optional<Double> amount() {
        String a = params.get("am");
        if (a == null || a.trim().isEmpty()) return Optional.empty();
        try {
            return Optional.of(Double.parseDouble(a));
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }

    /** A pull request: money leaves the scanner's account on approval. */
    public boolean isCollectOrMandate() {
        return action.contains("collect") || action.contains("mandate");
    }

    /** Any UPI request initiated by scanning debits the scanner (spec warning trigger). */
    public boolean initiatesDebit() {
        return valid; // pay, collect, mandate all debit the person who scans
    }

    private static String emptyToNull(String s) {
        return (s == null || s.trim().isEmpty()) ? null : s;
    }
}
