package com.cybershield.app.shield;

import android.view.accessibility.AccessibilityNodeInfo;

import java.util.ArrayDeque;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Client-side page inspection via the accessibility tree — the same idea as
 * Chrome's on-device phishing model: does the visible page look like a
 * brand's sign-in page while sitting on a domain that isn't that brand?
 *
 * <p>No network, no HTML fetch. We read what's already rendered: input fields
 * (is there a password box?), headings and visible text (which brand does it
 * claim to be?).
 */
final class BrowserPageReader {

    /** brand token -> its real registrable domain(s). */
    static final Map<String, String[]> BRAND_DOMAINS = new LinkedHashMap<>();
    static {
        BRAND_DOMAINS.put("paypal", new String[]{"paypal.com"});
        BRAND_DOMAINS.put("google", new String[]{"google.com", "accounts.google.com"});
        BRAND_DOMAINS.put("gmail", new String[]{"google.com"});
        BRAND_DOMAINS.put("microsoft", new String[]{"microsoft.com", "live.com", "office.com"});
        BRAND_DOMAINS.put("outlook", new String[]{"live.com", "microsoft.com"});
        BRAND_DOMAINS.put("apple", new String[]{"apple.com", "icloud.com"});
        BRAND_DOMAINS.put("amazon", new String[]{"amazon.com", "amazon.in"});
        BRAND_DOMAINS.put("facebook", new String[]{"facebook.com"});
        BRAND_DOMAINS.put("instagram", new String[]{"instagram.com"});
        BRAND_DOMAINS.put("netflix", new String[]{"netflix.com"});
        BRAND_DOMAINS.put("linkedin", new String[]{"linkedin.com"});
        BRAND_DOMAINS.put("whatsapp", new String[]{"whatsapp.com"});
        BRAND_DOMAINS.put("paytm", new String[]{"paytm.com"});
        BRAND_DOMAINS.put("phonepe", new String[]{"phonepe.com"});
        BRAND_DOMAINS.put("sbi", new String[]{"sbi.co.in", "onlinesbi.sbi"});
        BRAND_DOMAINS.put("hdfc", new String[]{"hdfcbank.com"});
        BRAND_DOMAINS.put("icici", new String[]{"icicibank.com"});
        BRAND_DOMAINS.put("axis", new String[]{"axisbank.com"});
        BRAND_DOMAINS.put("kotak", new String[]{"kotak.com"});
        BRAND_DOMAINS.put("irctc", new String[]{"irctc.co.in"});
        BRAND_DOMAINS.put("flipkart", new String[]{"flipkart.com"});
        BRAND_DOMAINS.put("binance", new String[]{"binance.com"});
        BRAND_DOMAINS.put("coinbase", new String[]{"coinbase.com"});
    }

    static final class Page {
        boolean hasPasswordField;
        boolean hasLoginText;
        String text = "";
    }

    private BrowserPageReader() {}

    static Page read(AccessibilityNodeInfo root) {
        Page p = new Page();
        if (root == null) return p;
        StringBuilder text = new StringBuilder();
        ArrayDeque<AccessibilityNodeInfo> q = new ArrayDeque<>();
        q.add(root);
        int budget = 1200;
        while (!q.isEmpty() && budget-- > 0) {
            AccessibilityNodeInfo n = q.poll();
            if (n == null) continue;

            if (n.isPassword()) p.hasPasswordField = true;
            CharSequence cls = n.getClassName();
            if (cls != null && cls.toString().contains("EditText")) {
                CharSequence hint = n.getHintText();
                CharSequence desc = n.getContentDescription();
                String meta = ((hint == null ? "" : hint) + " " + (desc == null ? "" : desc)).toLowerCase(Locale.ROOT);
                if (meta.contains("password") || meta.contains("passcode")) p.hasPasswordField = true;
            }

            CharSequence t = n.getText();
            if (t != null && t.length() > 0 && text.length() < 4000) {
                text.append(t).append(' ');
            }
            for (int i = 0; i < n.getChildCount(); i++) {
                AccessibilityNodeInfo c = n.getChild(i);
                if (c != null) q.add(c);
            }
        }
        p.text = text.toString().toLowerCase(Locale.ROOT);
        p.hasLoginText = p.text.contains("sign in") || p.text.contains("log in") || p.text.contains("login")
                || p.text.contains("forgot password") || p.text.contains("keep me signed in");
        return p;
    }

    /**
     * @return the impersonated brand if the page looks like a sign-in page for a
     *         brand whose real domain is NOT {@code host}; else null.
     */
    static String impersonatedBrand(Page p, String host) {
        if (host == null || !(p.hasPasswordField || p.hasLoginText)) return null;
        String h = host.toLowerCase(Locale.ROOT);
        for (Map.Entry<String, String[]> e : BRAND_DOMAINS.entrySet()) {
            String brand = e.getKey();
            if (!p.text.contains(brand)) continue;
            boolean onRealDomain = false;
            for (String d : e.getValue()) {
                if (h.equals(d) || h.endsWith("." + d)) { onRealDomain = true; break; }
            }
            if (!onRealDomain) return brand;
        }
        return null;
    }
}
