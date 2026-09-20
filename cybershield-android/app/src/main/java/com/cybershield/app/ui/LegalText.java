package com.cybershield.app.ui;

import android.content.Context;
import android.text.method.ScrollingMovementMethod;
import android.util.TypedValue;
import android.widget.TextView;

import androidx.appcompat.app.AlertDialog;

/** The Secure Me Terms &amp; Conditions and Privacy notice shown at sign-up. */
public final class LegalText {

    public static final String VERSION = "2026-09";

    private LegalText() {}

    public static final String TEXT =
            "SECURE ME - TERMS & CONDITIONS AND PRIVACY NOTICE\n"
            + "Version " + VERSION + "\n\n"

            + "1. What Secure Me does\n"
            + "Secure Me checks links, messages, emails, QR codes and payment requests and warns you about likely "
            + "scams, phishing and fraud. It is a helper for your own decisions. It is not a guarantee: a check can "
            + "sometimes be wrong, so always confirm with the official source before you pay or share details.\n\n"

            + "2. Your account\n"
            + "Give correct details, keep your password secret (12 or more characters) and do not share your "
            + "one-time codes with anyone. You are responsible for activity on your account. If you are under 18, "
            + "use Secure Me only with the consent of a parent or guardian.\n\n"

            + "3. What we collect, and why\n"
            + "- Account details: email, username, display name, and your password stored only as a one-way hash.\n"
            + "- Consent record: the time you accepted these terms and which version.\n"
            + "- Security details: sign-in time and IP address, used to send you sign-in alerts and to stop abuse.\n"
            + "- Scan history: a redacted summary of what you checked and the result. Old records are removed "
            + "automatically after about 30 days.\n"
            + "- Reports you choose to send, and your location only if you file an incident report.\n\n"

            + "4. Permissions the app asks for\n"
            + "- SMS: to read incoming messages on your phone and warn you about scam texts. Message text is "
            + "checked on your device; only a redacted summary is kept in your history.\n"
            + "- Camera: to scan QR codes.\n"
            + "- Notifications: to show scam warnings.\n"
            + "- Accessibility: to read the address bar of supported web browsers and warn you about dangerous "
            + "websites. It is used for nothing else, and it does not read other apps or payment screens.\n"
            + "- Location: only when you file an incident report.\n"
            + "You can turn any permission off in your phone's settings; some features will then stop working.\n\n"

            + "5. How we protect your data\n"
            + "We process as much as possible on your phone, hide personal details before anything is stored, "
            + "hash identifiers, and encrypt data in transit. We do not sell your data.\n\n"

            + "6. Emails from us\n"
            + "We send verification codes, password-reset codes, sign-in alerts and threat alerts. Secure Me will "
            + "never ask you for your OTP, PIN, password or card number by email, SMS or call.\n\n"

            + "7. Your rights\n"
            + "Under the Digital Personal Data Protection Act, 2023, you may ask to see, correct or erase your "
            + "data, withdraw your consent, or raise a complaint. Contact the Secure Me team through the app. "
            + "Withdrawing consent means we can no longer keep your account.\n\n"

            + "8. Reports and the authorities\n"
            + "If you choose to continue past a high-risk warning (after confirming with your fingerprint or PIN), "
            + "the address of that site (without its query string) and its risk score are sent to the Secure Me "
            + "dashboard so the team can protect other users. "
            + "If you file an incident report, it may be shared with the cyber-crime authorities so they can act "
            + "on it. If you have already lost money, call 1930 or go to cybercrime.gov.in straight away.\n\n"

            + "9. Fair use\n"
            + "Do not misuse Secure Me: no false reports, no attacking or overloading the service, no automated "
            + "scraping, and no using it to harass anyone. We may limit or close accounts that do.\n\n"

            + "10. Limits of responsibility\n"
            + "Secure Me is provided as it is. To the extent the law allows, we are not responsible for losses "
            + "caused by a missed threat, a wrong warning, or the service being unavailable. Your payment "
            + "decisions remain yours.\n\n"

            + "11. Changes\n"
            + "We may update these terms. If a change is important, we will ask you to accept the new version.\n\n"

            + "12. Governing law\n"
            + "These terms are governed by the laws of India.\n";

    /** Shows the full text; the "I agree" button calls {@code onAgree}. */
    public static void show(Context ctx, Runnable onAgree) {
        TextView tv = new TextView(ctx);
        tv.setText(TEXT);
        tv.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        int pad = (int) (20 * ctx.getResources().getDisplayMetrics().density);
        tv.setPadding(pad, pad / 2, pad, pad / 2);
        tv.setMovementMethod(new ScrollingMovementMethod());
        tv.setVerticalScrollBarEnabled(true);
        tv.setMaxHeight((int) (ctx.getResources().getDisplayMetrics().heightPixels * 0.62));

        new AlertDialog.Builder(ctx)
                .setTitle("Terms & Conditions")
                .setView(tv)
                .setPositiveButton("I agree", (d, w) -> {
                    if (onAgree != null) onAgree.run();
                })
                .setNegativeButton("Close", null)
                .show();
    }
}
