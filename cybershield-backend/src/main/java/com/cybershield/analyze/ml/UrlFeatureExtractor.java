package com.cybershield.analyze.ml;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Lexical URL features — the Java twin of {@code ml/url_features.py}.
 *
 * <p>Every value is derived from the URL string alone (no DNS, no fetch), so the
 * exact same numbers are produced here, in the Python trainer, and in the
 * Android on-device copy. Order of {@link #FEATURES} is the model's input order.
 * If you change anything here, change all three and retrain.
 */
public final class UrlFeatureExtractor {

    public static final String[] FEATURES = {
            "url_length", "host_length", "path_length", "query_length",
            "num_dots", "num_hyphens", "num_digits", "num_special",
            "num_subdomains", "num_params",
            "has_ip", "has_at", "has_punycode", "pct_encoded",
            "suspicious_tld", "is_https", "is_shortener",
            "host_entropy", "url_entropy",
            "suspicious_keywords", "longest_token", "digit_ratio_host",
            "hyphen_in_domain", "tld_length",
    };

    private static final Set<String> SUSPICIOUS_TLDS = Set.of(
            "zip", "mov", "top", "xyz", "club", "online", "click", "country",
            "gq", "cf", "tk", "ml", "work", "support", "rest", "fit", "buzz",
            "info", "biz");

    private static final Set<String> SHORTENERS = Set.of(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
            "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "bl.ink",
            "t.ly", "short.io");

    private static final String[] SUSPICIOUS_KEYWORDS = {
            "login", "signin", "verify", "verification", "account", "secure",
            "security", "update", "password", "wallet", "payment", "refund",
            "reward", "prize", "claim", "bank", "otp", "kyc", "invoice", "urgent",
            "confirm", "unlock", "suspend", "recover"};

    private static final Pattern SCHEME = Pattern.compile("(?i)^[a-z][a-z0-9+.\\-]*://");
    private static final Pattern IPV4 = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");
    private static final Pattern PCT = Pattern.compile("%[0-9a-fA-F]{2}");
    private static final Pattern SEP = Pattern.compile("[.\\-_]");
    private static final String SPECIAL_ALLOWED = "./:-_?=&%@";

    private UrlFeatureExtractor() {}

    /** Feature name -> value, in {@link #FEATURES} order. */
    public static Map<String, Double> extract(String url) {
        String raw = url == null ? "" : url.trim();
        if (!SCHEME.matcher(raw).find()) raw = "http://" + raw;

        String afterScheme = raw.contains("://") ? raw.substring(raw.indexOf("://") + 3) : raw;
        String authority = split(afterScheme, "/?#");
        String rest = afterScheme.substring(authority.length());
        String hostPort = authority.contains("@") ? authority.substring(authority.lastIndexOf('@') + 1) : authority;
        String host = hostPort;
        int colon = host.indexOf(':');
        if (colon >= 0) host = host.substring(0, colon);
        host = host.toLowerCase();
        while (host.endsWith(".")) host = host.substring(0, host.length() - 1);

        String path = rest;
        String query = "";
        int q = rest.indexOf('?');
        if (q >= 0) {
            path = rest.substring(0, q);
            query = rest.substring(q + 1);
            int h = query.indexOf('#');
            if (h >= 0) query = query.substring(0, h);
        } else {
            int h = path.indexOf('#');
            if (h >= 0) path = path.substring(0, h);
        }

        String scheme = raw.substring(0, Math.max(0, raw.indexOf("://"))).toLowerCase();

        String[] labels = host.isEmpty() ? new String[0] : host.split("\\.", -1);
        String tld = labels.length >= 2 ? labels[labels.length - 1] : "";
        String domainLabel = labels.length >= 2 ? labels[labels.length - 2] : host;
        String domain = labels.length >= 2
                ? labels[labels.length - 2] + "." + labels[labels.length - 1] : host;

        int wwwOffset = (labels.length > 0 && labels[0].equals("www")) ? 1 : 0;
        int numSubdomains = Math.max(0, (labels.length - wwwOffset) - 2);

        String lowerHp = (host + path).toLowerCase();
        int digitsHost = countDigits(host);

        int numSpecial = 0;
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (!Character.isLetterOrDigit(c) && SPECIAL_ALLOWED.indexOf(c) < 0) numSpecial++;
        }

        int suspKeywords = 0;
        for (String k : SUSPICIOUS_KEYWORDS) if (lowerHp.contains(k)) suspKeywords++;

        int longestToken = 0;
        for (String t : SEP.split(host)) if (t.length() > longestToken) longestToken = t.length();

        int pctEncoded = 0;
        Matcher m = PCT.matcher(raw);
        while (m.find()) pctEncoded++;

        int numParams = 0;
        if (!query.isEmpty()) for (String p : query.split("&")) if (!p.isEmpty()) numParams++;

        Map<String, Double> f = new LinkedHashMap<>();
        f.put("url_length", (double) raw.length());
        f.put("host_length", (double) host.length());
        f.put("path_length", (double) path.length());
        f.put("query_length", (double) query.length());
        f.put("num_dots", (double) count(raw, '.'));
        f.put("num_hyphens", (double) count(raw, '-'));
        f.put("num_digits", (double) countDigits(raw));
        f.put("num_special", (double) numSpecial);
        f.put("num_subdomains", (double) numSubdomains);
        f.put("num_params", (double) numParams);
        f.put("has_ip", IPV4.matcher(host).matches() ? 1.0 : 0.0);
        f.put("has_at", afterScheme.contains("@") ? 1.0 : 0.0);
        f.put("has_punycode", host.contains("xn--") ? 1.0 : 0.0);
        f.put("pct_encoded", (double) pctEncoded);
        f.put("suspicious_tld", SUSPICIOUS_TLDS.contains(tld) ? 1.0 : 0.0);
        f.put("is_https", scheme.equals("https") ? 1.0 : 0.0);
        f.put("is_shortener", SHORTENERS.contains(domain) ? 1.0 : 0.0);
        f.put("host_entropy", round4(entropy(host)));
        f.put("url_entropy", round4(entropy(raw)));
        f.put("suspicious_keywords", (double) suspKeywords);
        f.put("longest_token", (double) longestToken);
        f.put("digit_ratio_host", host.isEmpty() ? 0.0 : round4((double) digitsHost / host.length()));
        f.put("hyphen_in_domain", domainLabel.indexOf('-') >= 0 ? 1.0 : 0.0);
        f.put("tld_length", (double) tld.length());
        return f;
    }

    public static double[] vector(String url) {
        Map<String, Double> f = extract(url);
        double[] v = new double[FEATURES.length];
        for (int i = 0; i < FEATURES.length; i++) v[i] = f.getOrDefault(FEATURES[i], 0.0);
        return v;
    }

    private static String split(String s, String stops) {
        for (int i = 0; i < s.length(); i++) if (stops.indexOf(s.charAt(i)) >= 0) return s.substring(0, i);
        return s;
    }

    private static int count(String s, char c) {
        int n = 0;
        for (int i = 0; i < s.length(); i++) if (s.charAt(i) == c) n++;
        return n;
    }

    private static int countDigits(String s) {
        int n = 0;
        for (int i = 0; i < s.length(); i++) if (Character.isDigit(s.charAt(i))) n++;
        return n;
    }

    private static double entropy(String s) {
        if (s == null || s.isEmpty()) return 0.0;
        int[] counts = new int[128];
        Map<Character, Integer> wide = new LinkedHashMap<>();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 128) counts[c]++;
            else wide.merge(c, 1, Integer::sum);
        }
        double n = s.length();
        double h = 0.0;
        for (int c : counts) if (c > 0) h -= (c / n) * (Math.log(c / n) / Math.log(2));
        for (int c : wide.values()) h -= (c / n) * (Math.log(c / n) / Math.log(2));
        return h;
    }

    private static double round4(double v) {
        return Math.round(v * 10000.0) / 10000.0;
    }
}
