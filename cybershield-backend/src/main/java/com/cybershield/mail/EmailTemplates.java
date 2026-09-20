package com.cybershield.mail;

/**
 * Inline-HTML email bodies for Secure Me. Light, plain layout that reads well in every mail app
 * (and in dark mode), with simple wording. No external assets.
 */
final class EmailTemplates {

    private static final String BRAND = "#0b6b4f";      // deep green
    private static final String BRAND_SOFT = "#ecfdf5"; // pale green
    private static final String INK = "#1f2937";
    private static final String MUTED = "#6b7280";
    private static final String LINE = "#e5e9ef";

    private EmailTemplates() {}

    static String wrap(String appName, String body) {
        return """
            <div style="background:#f4f6f8;padding:24px 12px;font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif">
              <div style="max-width:520px;margin:0 auto;background:#ffffff;border:1px solid %s;border-radius:14px;overflow:hidden">
                <div style="background:%s;padding:18px 24px;color:#ffffff;font-size:20px;font-weight:700;letter-spacing:.3px">
                  &#128737;&#65039; %s
                </div>
                <div style="padding:26px 24px;color:%s;font-size:15px;line-height:1.65">
                  %s
                </div>
                <div style="padding:16px 24px;background:#f9fafb;border-top:1px solid %s;color:%s;font-size:12px;line-height:1.55">
                  <b>%s</b> helps you stay safe from scam messages, fake websites and payment fraud.<br>
                  This is an automated message, please do not reply. Never share your code with anyone -
                  %s will never ask you for it.
                </div>
              </div>
            </div>
            """.formatted(LINE, BRAND, appName, INK, body, LINE, MUTED, appName, appName);
    }

    private static String code(String c) {
        return "<div style=\"font-size:32px;letter-spacing:8px;font-weight:700;color:" + BRAND
                + ";background:" + BRAND_SOFT + ";border:1px solid #a7f3d0;border-radius:10px;"
                + "padding:14px 10px;text-align:center;margin:18px 0\">" + c + "</div>";
    }

    private static String small(String text) {
        return "<p style=\"color:" + MUTED + ";font-size:13px;margin:12px 0 0\">" + text + "</p>";
    }

    static String verification(String name, String c, String expires) {
        return "<p style=\"margin-top:0\">Hi " + esc(name) + ",</p>"
                + "<p>Welcome to Secure Me! Please confirm your email address with this code:</p>"
                + code(c)
                + "<p>Enter it in the Secure Me app to finish creating your account.</p>"
                + small("The code is valid for 15 minutes (until " + esc(expires) + "). "
                + "If you did not sign up, you can safely ignore this email.");
    }

    static String welcome(String name) {
        return "<p style=\"margin-top:0\">Hi " + esc(name) + ",</p>"
                + "<p>Your Secure Me account is ready. &#127881;</p>"
                + "<p>Sign in on the Secure Me app or the browser extension to check links, messages, "
                + "QR codes and payments before you trust them.</p>"
                + "<p>We will email you if a new device signs in to your account, or if we block a "
                + "serious threat aimed at you.</p>";
    }

    static String signInAlert(String name, String when) {
        return "<p style=\"margin-top:0\">Hi " + esc(name) + ",</p>"
                + "<p>Your Secure Me account was signed in on <b>" + esc(when) + "</b>.</p>"
                + "<p>If that was you, there is nothing to do.</p>"
                + "<p><b>If it was not you</b>, open the Secure Me app and choose "
                + "<b>Forgot password</b> right away to lock the person out.</p>";
    }

    static String passwordReset(String name, String c, String link, String expires) {
        String linkBtn = (link == null || link.isBlank()) ? "" :
                "<p style=\"margin:18px 0\"><a href=\"" + esc(link) + "\" "
                + "style=\"background:" + BRAND + ";color:#ffffff;text-decoration:none;padding:11px 18px;"
                + "border-radius:8px;font-weight:600;display:inline-block\">Open in the Secure Me app</a></p>";
        return "<p style=\"margin-top:0\">Hi " + esc(name) + ",</p>"
                + "<p>We got a request to reset your Secure Me password. Use this code:</p>"
                + code(c)
                + linkBtn
                + small("The code is valid for 15 minutes (until " + esc(expires) + "). "
                + "If you did not ask for this, ignore this email. Your password stays the same.");
    }

    static String passwordChanged(String name, String when) {
        return "<p style=\"margin-top:0\">Hi " + esc(name) + ",</p>"
                + "<p>Your Secure Me password was changed on <b>" + esc(when) + "</b>.</p>"
                + "<p>If you did this, all good. If you did not, use <b>Forgot password</b> in the app "
                + "immediately to secure your account.</p>";
    }

    static String threatAlert(String name, String type, String level, int score, String topSignal, String snippet) {
        return "<p style=\"margin-top:0\">Hi " + esc(name) + ",</p>"
                + "<p>Secure Me checked something for you and marked it "
                + "<b style=\"color:#b91c1c\">" + esc(level.replace('_', ' ')) + "</b> (risk " + score + " out of 100).</p>"
                + "<table style=\"width:100%;border-collapse:collapse;font-size:14px\">"
                + row("Type", type) + row("Main reason", topSignal) + row("What it said", snippet)
                + "</table>"
                + "<p><b>Do not</b> click links, share codes or details, or send money because of it. "
                + "Please report it in the app so others are protected too.</p>";
    }

    private static String row(String k, String v) {
        return "<tr><td style=\"padding:8px 10px;border-bottom:1px solid " + LINE + ";color:" + MUTED
                + ";width:34%\">" + esc(k) + "</td><td style=\"padding:8px 10px;border-bottom:1px solid "
                + LINE + "\">" + esc(v) + "</td></tr>";
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
