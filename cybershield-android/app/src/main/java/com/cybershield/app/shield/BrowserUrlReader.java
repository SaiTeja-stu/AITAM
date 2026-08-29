package com.cybershield.app.shield;

import android.view.accessibility.AccessibilityNodeInfo;

import java.util.ArrayDeque;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Pulls the address-bar URL out of a browser window via the accessibility tree.
 *
 * <p>Most browsers expose the location bar under a stable view id. When the bar
 * is collapsed the text is usually just the registrable domain (e.g.
 * {@code "paypa1-verify.tk"}); when the user is editing it we get the full URL.
 * Either is enough for a domain-level safety check.
 */
final class BrowserUrlReader {

    /** package name -> location-bar view id resource names to try, in order. */
    private static final String[][] KNOWN = {
            {"com.android.chrome", "com.android.chrome:id/url_bar"},
            {"com.chrome.beta", "com.chrome.beta:id/url_bar"},
            {"com.chrome.dev", "com.chrome.dev:id/url_bar"},
            {"com.brave.browser", "com.brave.browser:id/url_bar"},
            {"com.microsoft.emmx", "com.microsoft.emmx:id/url_bar"},
            {"com.sec.android.app.sbrowser", "com.sec.android.app.sbrowser:id/location_bar_edit_text"},
            {"com.opera.browser", "com.opera.browser:id/url_field"},
            {"com.opera.mini.native", "com.opera.mini.native:id/url_field"},
            {"org.mozilla.firefox", "org.mozilla.firefox:id/mozac_browser_toolbar_url_view"},
            {"org.mozilla.firefox", "org.mozilla.firefox:id/url_bar_title"},
            {"com.duckduckgo.mobile.android", "com.duckduckgo.mobile.android:id/omnibarTextInput"},
    };

    private static final Pattern LOOKS_LIKE_HOST =
            Pattern.compile("(?i)^([a-z0-9-]+\\.)+[a-z]{2,}(/.*)?$");

    private BrowserUrlReader() {}

    static boolean isBrowser(String pkg) {
        if (pkg == null) return false;
        for (String[] row : KNOWN) if (row[0].equals(pkg)) return true;
        return false;
    }

    /** Best-effort URL/host from the active window, or null. */
    static String read(AccessibilityNodeInfo root, String pkg) {
        if (root == null) return null;

        // 1. try the known location-bar id(s) for this browser
        for (String[] row : KNOWN) {
            if (!row[0].equals(pkg)) continue;
            List<AccessibilityNodeInfo> hits = root.findAccessibilityNodeInfosByViewId(row[1]);
            if (hits != null) {
                for (AccessibilityNodeInfo n : hits) {
                    String v = textOf(n);
                    n.recycle();
                    String u = clean(v);
                    if (u != null) return u;
                }
            }
        }

        // 2. generic sweep: an editable node, or any node whose id ends in url/omnibox/location
        AccessibilityNodeInfo found = sweep(root);
        return found == null ? null : clean(textOf(found));
    }

    private static AccessibilityNodeInfo sweep(AccessibilityNodeInfo root) {
        ArrayDeque<AccessibilityNodeInfo> q = new ArrayDeque<>();
        q.add(root);
        int budget = 400;
        while (!q.isEmpty() && budget-- > 0) {
            AccessibilityNodeInfo n = q.poll();
            if (n == null) continue;
            CharSequence id = n.getViewIdResourceName();
            if (id != null) {
                String s = id.toString().toLowerCase(Locale.ROOT);
                if (s.endsWith("url_bar") || s.contains("omnibox") || s.contains("url_field")
                        || s.endsWith("location_bar_edit_text") || s.contains("mozac_browser_toolbar_url")) {
                    if (clean(textOf(n)) != null) return n;
                }
            }
            for (int i = 0; i < n.getChildCount(); i++) {
                AccessibilityNodeInfo c = n.getChild(i);
                if (c != null) q.add(c);
            }
        }
        return null;
    }

    private static String textOf(AccessibilityNodeInfo n) {
        if (n == null) return null;
        CharSequence t = n.getText();
        if (t == null || t.length() == 0) t = n.getContentDescription();
        return t == null ? null : t.toString().trim();
    }

    /** Normalise what the bar showed into something the engine can parse, or null. */
    private static String clean(String raw) {
        if (raw == null) return null;
        String s = raw.trim();
        if (s.isEmpty()) return null;
        int sp = s.indexOf(' ');           // some bars append " - Secure" / page title
        if (sp > 8) s = s.substring(0, sp);
        if (s.regionMatches(true, 0, "http://", 0, 7) || s.regionMatches(true, 0, "https://", 0, 8)) {
            return s;
        }
        // Chrome's collapsed bar shows just the domain of the CURRENT page, which
        // today is virtually always HTTPS — assume https so we don't wrongly fire
        // the "no HTTPS" signal on legitimate sites.
        if (LOOKS_LIKE_HOST.matcher(s).matches()) return "https://" + s;
        return null;                        // search terms, "New tab", etc.
    }
}
