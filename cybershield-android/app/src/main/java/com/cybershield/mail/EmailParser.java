package com.cybershield.mail;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pragmatic RFC-822 parser: enough to analyse a phishing email that a user
 * pasted from Gmail's "Show original", forwarded, or dropped in as a {@code .eml}.
 *
 * <p>It does NOT do full MIME decoding. It unfolds headers, pulls the fields that
 * matter, reads the receiver-stamped {@code Authentication-Results}
 * (SPF/DKIM/DMARC), strips HTML from the body and lists the links.
 */
public final class EmailParser {

    private static final Pattern ADDR = Pattern.compile("<([^<>@\\s]+@[^<>@\\s]+)>|([^<>@\\s]+@[^<>@\\s]+)");
    private static final Pattern AUTH_KV = Pattern.compile("(?i)\\b(spf|dkim|dmarc)\\s*=\\s*([a-z]+)");
    private static final Pattern RECEIVED_IP =
            Pattern.compile("[\\[(](\\d{1,3}(?:\\.\\d{1,3}){3})[\\])]");
    private static final Pattern URL_IN_TEXT =
            Pattern.compile("(?i)\\b((?:https?://|www\\.)[^\\s\"'<>()]+)");
    private static final Pattern TAG = Pattern.compile("(?s)<[^>]+>");
    private static final Pattern HREF = Pattern.compile("(?i)href\\s*=\\s*[\"']([^\"']+)[\"']");

    private EmailParser() {}

    public static EmailMessage parse(String raw) {
        String s = raw == null ? "" : raw.replace("\r\n", "\n").replace("\r", "\n");

        int split = indexOfBlankLine(s);
        boolean hadHeaders;
        String headerBlock, body;
        if (split >= 0 && looksLikeHeaders(s.substring(0, split))) {
            headerBlock = s.substring(0, split);
            body = s.substring(split).replaceAll("^\\s+", "");
            hadHeaders = true;
        } else if (looksLikeHeaders(s)) {          // headers only, no body
            headerBlock = s;
            body = "";
            hadHeaders = true;
        } else {
            headerBlock = "";
            body = s;
            hadHeaders = false;
        }

        Map<String, List<String>> h = headers(headerBlock);

        String fromRaw = first(h, "from");
        String display = displayName(fromRaw);
        String fromAddr = address(fromRaw).toLowerCase(Locale.ROOT);
        String fromDomain = domainOf(fromAddr);

        String replyTo = address(first(h, "reply-to")).toLowerCase(Locale.ROOT);
        String returnPath = domainOf(address(first(h, "return-path")).toLowerCase(Locale.ROOT));

        EmailMessage.Auth spf = EmailMessage.Auth.UNKNOWN;
        EmailMessage.Auth dkim = EmailMessage.Auth.UNKNOWN;
        EmailMessage.Auth dmarc = EmailMessage.Auth.UNKNOWN;
        for (String ar : h.getOrDefault("authentication-results", List.of())) {
            Matcher m = AUTH_KV.matcher(ar);
            while (m.find()) {
                EmailMessage.Auth v = toAuth(m.group(2));
                switch (m.group(1).toLowerCase(Locale.ROOT)) {
                    case "spf" -> spf = merge(spf, v);
                    case "dkim" -> dkim = merge(dkim, v);
                    case "dmarc" -> dmarc = merge(dmarc, v);
                    default -> { }
                }
            }
        }
        if (spf == EmailMessage.Auth.UNKNOWN) {
            String rs = first(h, "received-spf").toLowerCase(Locale.ROOT);
            if (rs.startsWith("pass")) spf = EmailMessage.Auth.PASS;
            else if (rs.startsWith("fail") || rs.startsWith("softfail")) spf = EmailMessage.Auth.FAIL;
        }

        String ip = "";
        List<String> received = h.getOrDefault("received", List.of());
        if (!received.isEmpty()) {
            Matcher m = RECEIVED_IP.matcher(received.get(received.size() - 1)); // earliest hop = last header
            if (m.find()) ip = m.group(1);
        }

        String text = stripHtml(body);
        List<String> links = links(body, text);

        return new EmailMessage(display, fromAddr, fromDomain, replyTo, returnPath,
                first(h, "subject"), spf, dkim, dmarc, ip, text, links, hadHeaders);
    }

    // --- headers --------------------------------------------------------

    private static int indexOfBlankLine(String s) {
        int i = s.indexOf("\n\n");
        return i;
    }

    private static boolean looksLikeHeaders(String block) {
        // at least one line matching "Header-Name: value" near the top
        int lines = 0;
        for (String line : block.split("\n")) {
            if (line.trim().isEmpty()) break;
            if (line.matches("(?i)^[a-z][a-z0-9-]{1,40}:\\s?.*") || line.matches("^[ \\t].*")) {
                if (++lines >= 1 && line.toLowerCase(Locale.ROOT).matches("(?i)^(from|to|subject|received|date|authentication-results|return-path):.*")) {
                    return true;
                }
            } else if (lines == 0) {
                return false;
            }
        }
        return false;
    }

    private static Map<String, List<String>> headers(String block) {
        Map<String, List<String>> h = new LinkedHashMap<>();
        if (block.isEmpty()) return h;
        String[] lines = block.split("\n");
        String curKey = null;
        StringBuilder curVal = new StringBuilder();
        for (String line : lines) {
            if (line.startsWith(" ") || line.startsWith("\t")) {       // folded continuation
                if (curKey != null) curVal.append(' ').append(line.trim());
                continue;
            }
            int c = line.indexOf(':');
            if (c <= 0) continue;
            if (curKey != null) {
                h.computeIfAbsent(curKey, k -> new ArrayList<>()).add(curVal.toString().trim());
            }
            curKey = line.substring(0, c).trim().toLowerCase(Locale.ROOT);
            curVal.setLength(0);
            curVal.append(line.substring(c + 1).trim());
        }
        if (curKey != null) {
            h.computeIfAbsent(curKey, k -> new ArrayList<>()).add(curVal.toString().trim());
        }
        return h;
    }

    private static String first(Map<String, List<String>> h, String key) {
        List<String> v = h.get(key);
        return v == null || v.isEmpty() ? "" : v.get(0);
    }

    // --- field extraction ---------------------------------------------

    static String displayName(String fromRaw) {
        if (fromRaw == null || fromRaw.trim().isEmpty()) return "";
        String s = fromRaw.trim();
        int lt = s.indexOf('<');
        if (lt > 0) {
            return s.substring(0, lt).trim().replaceAll("^\"|\"$", "").trim();
        }
        return "";
    }

    static String address(String raw) {
        if (raw == null) return "";
        Matcher m = ADDR.matcher(raw);
        if (m.find()) {
            return (m.group(1) != null ? m.group(1) : m.group(2)).trim();
        }
        return "";
    }

    static String domainOf(String addr) {
        int at = addr == null ? -1 : addr.indexOf('@');
        if (at < 0) return "";
        String host = addr.substring(at + 1).trim().toLowerCase(Locale.ROOT);
        String[] p = host.split("\\.");
        if (p.length < 2) return host;
        if (p.length >= 3) {
            String l2 = p[p.length - 2] + "." + p[p.length - 1];
            if (l2.matches("(co|com|net|org|gov|edu|ac|gob)\\.[a-z]{2}")) {
                return p[p.length - 3] + "." + l2;
            }
        }
        return p[p.length - 2] + "." + p[p.length - 1];
    }

    private static EmailMessage.Auth toAuth(String v) {
        return switch (v.toLowerCase(Locale.ROOT)) {
            case "pass" -> EmailMessage.Auth.PASS;
            case "fail", "softfail", "permerror", "temperror", "policy", "neutral" -> EmailMessage.Auth.FAIL;
            case "none" -> EmailMessage.Auth.NONE;
            default -> EmailMessage.Auth.UNKNOWN;
        };
    }

    /** FAIL wins over PASS wins over NONE — worst observed result across headers. */
    private static EmailMessage.Auth merge(EmailMessage.Auth a, EmailMessage.Auth b) {
        if (a == EmailMessage.Auth.FAIL || b == EmailMessage.Auth.FAIL) return EmailMessage.Auth.FAIL;
        if (a == EmailMessage.Auth.PASS || b == EmailMessage.Auth.PASS) return EmailMessage.Auth.PASS;
        if (a == EmailMessage.Auth.NONE || b == EmailMessage.Auth.NONE) return EmailMessage.Auth.NONE;
        return EmailMessage.Auth.UNKNOWN;
    }

    // --- body ---------------------------------------------------------

    private static String stripHtml(String body) {
        if (body == null) return "";
        if (!body.contains("<")) return body.trim();
        String t = body.replaceAll("(?is)<(script|style)[^>]*>.*?</\\1>", " ");
        t = TAG.matcher(t).replaceAll(" ");
        t = t.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">");
        return t.replaceAll("[ \\t]+", " ").replaceAll("\n{3,}", "\n\n").trim();
    }

    private static List<String> links(String body, String text) {
        List<String> out = new ArrayList<>();
        Matcher h = HREF.matcher(body == null ? "" : body);
        while (h.find() && out.size() < 25) add(out, h.group(1));
        Matcher m = URL_IN_TEXT.matcher(text == null ? "" : text);
        while (m.find() && out.size() < 25) add(out, m.group(1));
        return out;
    }

    private static void add(List<String> out, String u) {
        if (u == null) return;
        String s = u.trim();
        if (s.startsWith("www.")) s = "http://" + s;
        if ((s.startsWith("http://") || s.startsWith("https://")) && !out.contains(s)) out.add(s);
    }
}
