package com.cybershield.app.engine;

import android.net.Uri;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** URL extraction / host parsing helpers. */
public final class Extract {

    private static final Pattern URL_IN_TEXT =
            Pattern.compile("(?i)\\b((?:https?://|www\\.)[^\\s\"'<>()]+)");

    private Extract() {}

    public static List<String> urls(String text) {
        List<String> out = new ArrayList<>();
        if (text == null) return out;
        Matcher m = URL_IN_TEXT.matcher(text);
        int n = 0;
        while (m.find() && n++ < 10) {
            String u = m.group(1);
            if (u.startsWith("www.")) u = "http://" + u;
            out.add(u);
        }
        return out;
    }

    public static String host(String url) {
        if (url == null) return null;
        try {
            String s = url.trim();
            if (!s.matches("(?i)^[a-z][a-z0-9+.-]*://.*")) s = "http://" + s;
            Uri u = Uri.parse(s);
            String h = u.getHost();
            if (h == null) return null;
            h = h.toLowerCase(Locale.ROOT);
            return h.endsWith(".") ? h.substring(0, h.length() - 1) : h;
        } catch (Exception e) {
            return null;
        }
    }
}
