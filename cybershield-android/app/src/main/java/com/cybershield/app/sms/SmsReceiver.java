package com.cybershield.app.sms;

import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.provider.Telephony;
import android.telephony.SmsMessage;

import androidx.core.app.NotificationCompat;

import com.cybershield.app.CyberShieldApp;
import com.cybershield.app.R;
import com.cybershield.app.data.Repository;
import com.cybershield.app.engine.LocalVerdict;
import com.cybershield.app.net.dto.AnalyzeResponse;
import com.cybershield.app.shield.ShieldPrefs;
import com.cybershield.app.ui.VerdictActivity;
import com.cybershield.app.util.Redact;

/**
 * Inspects incoming SMS the way Truecaller triages: every message is classified
 * (OTP / bank alert / promo / spam / fraud) and only <b>spam / fraud</b> raises a
 * visible warning — a real OTP or debit alert never gets a "scam" popup.
 *
 * <p>Cyber Shield is not the default SMS app, so it cannot delete or hide the
 * message from the stock Messages app; it warns, explains why, and keeps a
 * running "N scam texts flagged" count.
 *
 * <p>Only the message body is processed by the engine. The sender is shown in
 * the warning but not stored.
 */
public class SmsReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        if (!Telephony.Sms.Intents.SMS_RECEIVED_ACTION.equals(intent.getAction())) return;

        StringBuilder body = new StringBuilder();
        String sender = null;
        SmsMessage[] messages = Telephony.Sms.Intents.getMessagesFromIntent(intent);
        if (messages == null) return;
        for (SmsMessage m : messages) {
            if (m == null) continue;
            if (m.getMessageBody() != null) body.append(m.getMessageBody());
            if (sender == null) sender = m.getDisplayOriginatingAddress();
        }
        String text = body.toString().trim();
        if (text.isEmpty()) return;
        final String from = sender == null ? "Unknown sender" : sender;
        scan(context.getApplicationContext(), from, text);
    }

    /** Run the full incoming-SMS pipeline for a given sender + body. Also used by the in-app tester. */
    public static void scan(Context appCtx, String from, String text) {
        Repository repo = new Repository(appCtx);
        SmsReceiver self = new SmsReceiver();
        repo.analyze("SMS", text, "sms", new Repository.Callback() {
            @Override public void onLocal(LocalVerdict local) {
                self.triage(appCtx, from, text, local.isBlocking(), local.level == LocalVerdict.Level.MALICIOUS,
                        local.reasons.isEmpty() ? null : local.reasons.get(0));
            }
            @Override public void onServer(AnalyzeResponse v) {
                boolean risky = "MALICIOUS".equals(v.riskLevel) || "HIGH_RISK".equals(v.riskLevel)
                        || "SUSPICIOUS".equals(v.riskLevel);
                boolean fraud = "MALICIOUS".equals(v.riskLevel) || "HIGH_RISK".equals(v.riskLevel);
                String reason = null;
                if (v.signals != null) for (AnalyzeResponse.Signal s : v.signals) {
                    if (s.weight > 0) { reason = s.name; break; }
                }
                self.triage(appCtx, from, text, risky, fraud, reason != null ? reason : v.explanation);
            }
            @Override public void onServerError(String message) { /* local result already handled */ }
        });
    }

    private void triage(Context ctx, String sender, String text, boolean risky, boolean fraud, String reason) {
        // community number-reputation: has this exact sender been reported+confirmed before?
        boolean reportedNumber = false;
        try {
            reportedNumber = com.cybershield.app.data.AppDatabase.get(ctx).blocklistDao()
                    .isBlocked(com.cybershield.app.data.BlockedIndicator.TYPE_PHONE,
                            com.cybershield.app.engine.Hashing.hmac(sender));
        } catch (Exception ignored) { }

        SmsClassifier.Category cat = reportedNumber ? SmsClassifier.Category.FRAUD
                : SmsClassifier.classify(sender, text, risky, fraud);
        if (!SmsClassifier.isAlertWorthy(cat)) return;   // OTP / bank / promo -> stay quiet

        if (reason == null && reportedNumber) {
            reason = "This sender has been reported for fraud by other Cyber Shield users";
        } else if (reason == null
                && SmsClassifier.impersonatesInstitution(text.toLowerCase())
                && !SmsClassifier.looksLikeRegisteredSender(sender)) {
            reason = "Claims to be from a bank/official body but was sent from a personal number — "
                    + "genuine institutional SMS only come from a registered sender ID (e.g. VM-HDFCBK)";
        }

        ShieldPrefs prefs = new ShieldPrefs(ctx);
        int total = prefs.bumpSpamSmsCount();

        boolean isFraud = cat == SmsClassifier.Category.FRAUD;
        String title = (isFraud ? "⚠ Fraud SMS" : "🚫 Spam SMS") + " — " + sender;
        String why = reason == null || reason.trim().isEmpty()
                ? (isFraud ? "This message is a scam. Do not click links or reply." : "Looks like unwanted spam.")
                : reason;
        String big = why + "\n\n“" + Redact.snippet(text) + "”"
                + "\n\nCyber Shield has flagged " + total + " scam text" + (total == 1 ? "" : "s") + " so far."
                + (isFraud ? "\nNever share OTP / PIN / card details. Don't tap links in this message." : "");

        Intent open = VerdictActivity.intent(ctx, "SMS", text, "sms");
        open.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        PendingIntent pi = PendingIntent.getActivity(ctx, (int) (System.currentTimeMillis() & 0xFFFF), open,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);

        NotificationCompat.Builder n = new NotificationCompat.Builder(ctx, CyberShieldApp.CHANNEL_ALERTS)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(title)
                .setContentText(why)
                .setStyle(new NotificationCompat.BigTextStyle().bigText(big))
                .setPriority(isFraud ? NotificationCompat.PRIORITY_HIGH : NotificationCompat.PRIORITY_DEFAULT)
                .setCategory(NotificationCompat.CATEGORY_ERROR)
                .setAutoCancel(true)
                .setContentIntent(pi);

        NotificationManager nm = ctx.getSystemService(NotificationManager.class);
        if (nm != null) nm.notify((int) (System.currentTimeMillis() & 0xFFFFFF), n.build());
    }
}
