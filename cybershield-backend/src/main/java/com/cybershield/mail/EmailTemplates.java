package com.cybershield.mail;

/** Plain inline-HTML email bodies. Kept deliberately simple - no external assets. */
final class EmailTemplates {

    private EmailTemplates() {}

    static String wrap(String appName, String body) {
        return """
            <div style="font-family:Segoe UI,Roboto,Arial,sans-serif;background:#0b1020;padding:24px">
              <div style="max-width:520px;margin:0 auto;background:#131a2e;border:1px solid #243050;border-radius:12px;overflow:hidden">
                <div style="padding:16px 20px;background:#0f1730;color:#e7ecf5;font-weight:700;font-size:16px">
                  &#128737;&#65039; %s
                </div>
                <div style="padding:20px;color:#e7ecf5;font-size:14px;line-height:1.6">
                  %s
                </div>
                <div style="padding:14px 20px;color:#93a0bc;font-size:12px;border-top:1px solid #243050">
                  This is an automated security message. If you did not expect it, you can ignore it -
                  no action is taken on your account without a code from this email.
                </div>
              </div>
            </div>
            """.formatted(appName, body);
    }

    private static String code(String c) {
        return "<div style=\"font-size:28px;letter-spacing:6px;font-weight:700;color:#38bdf8;"
                + "background:#0b1020;border:1px solid #243050;border-radius:8px;padding:12px;text-align:center;margin:14px 0\">"
                + c + "</div>";
    }

    static String verification(String name, String c, String expires) {
        return "<p>Hi " + esc(name) + ",</p>"
                + "<p>Use this code to verify your email address and activate your account:</p>"
                + code(c)
                + "<p style=\"color:#93a0bc\">The code expires at <b>" + esc(expires) + "</b>.</p>"
                + "<p>If you did not sign up, ignore this email.</p>";
    }

    static String welcome(String name) {
        return "<p>Hi " + esc(name) + ",</p>"
                + "<p>Your Cyber Shield account is now active. You can sign in on the app, the browser "
                + "extension, or the dashboard.</p>"
                + "<p>We'll email you when a new device signs in, and when we block a serious threat "
                + "aimed at you.</p>";
    }

    static String signInAlert(String name, String when) {
        return "<p>Hi " + esc(name) + ",</p>"
                + "<p>Your Cyber Shield account was just signed in at <b>" + esc(when) + "</b>.</p>"
                + "<p>If this was you, no action is needed. If it wasn't, "
                + "<b>reset your password immediately</b> from the app or dashboard.</p>";
    }

    static String passwordReset(String name, String c, String link, String expires) {
        String linkBtn = (link == null || link.isBlank()) ? "" :
                "<p style=\"margin:16px 0\"><a href=\"" + esc(link) + "\" "
                + "style=\"background:#38bdf8;color:#0b1020;text-decoration:none;padding:10px 16px;border-radius:8px;font-weight:600\">"
                + "Open reset page</a></p>";
        return "<p>Hi " + esc(name) + ",</p>"
                + "<p>We received a request to reset your password. Enter this code in the app/dashboard:</p>"
                + code(c)
                + linkBtn
                + "<p style=\"color:#93a0bc\">The code expires at <b>" + esc(expires) + "</b>. "
                + "If you didn't request this, ignore this email - your password stays unchanged.</p>";
    }

    static String passwordChanged(String name, String when) {
        return "<p>Hi " + esc(name) + ",</p>"
                + "<p>Your Cyber Shield password was changed at <b>" + esc(when) + "</b>.</p>"
                + "<p>If this wasn't you, contact support and reset your password again right away.</p>";
    }

    static String threatAlert(String name, String type, String level, int score, String topSignal, String snippet) {
        return "<p>Hi " + esc(name) + ",</p>"
                + "<p>Cyber Shield flagged something you checked as <b style=\"color:#f87171\">"
                + esc(level.replace('_', ' ')) + "</b> (risk " + score + "/100).</p>"
                + "<ul><li><b>Type:</b> " + esc(type) + "</li>"
                + "<li><b>Main reason:</b> " + esc(topSignal) + "</li>"
                + "<li><b>Content:</b> " + esc(snippet) + "</li></ul>"
                + "<p>Do not click any links, enter any details, or make any payment related to it. "
                + "Report it in the app so others are protected.</p>";
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
