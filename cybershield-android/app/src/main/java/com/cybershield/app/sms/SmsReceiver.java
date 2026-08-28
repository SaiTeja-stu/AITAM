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
import com.cybershield.app.ui.VerdictActivity;
import com.cybershield.app.util.Redact;

/**
 * Inspects incoming SMS. Runs the on-device check immediately; if it looks
 * risky, posts a high-priority notification that opens the full verdict.
 * Only the message body is processed - sender number is not stored.
 */
public class SmsReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        if (!Telephony.Sms.Intents.SMS_RECEIVED_ACTION.equals(intent.getAction())) return;

        StringBuilder body = new StringBuilder();
        SmsMessage[] messages = Telephony.Sms.Intents.getMessagesFromIntent(intent);
        if (messages == null) return;
        for (SmsMessage m : messages) {
            if (m != null && m.getMessageBody() != null) body.append(m.getMessageBody());
        }
        String text = body.toString().trim();
        if (text.isEmpty()) return;

        Repository repo = new Repository(context.getApplicationContext());
        repo.analyze("SMS", text, "sms", new Repository.Callback() {
            @Override public void onLocal(LocalVerdict local) {
                if (local.isBlocking()) notifyRisk(context, text, local.priority(), local.reasons.isEmpty()
                        ? "This message looks like a scam." : local.reasons.get(0));
            }
            @Override public void onServer(AnalyzeResponse server) {
                if (server.isBlocking()) notifyRisk(context, text, server.priority,
                        server.explanation != null ? server.explanation : "This message looks like a scam.");
            }
            @Override public void onServerError(String message) { /* local result already handled */ }
        });
    }

    private void notifyRisk(Context ctx, String text, String priority, String summary) {
        Intent piIntent = VerdictActivity.intent(ctx, "SMS", text, "sms");
        piIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        PendingIntent pi = PendingIntent.getActivity(ctx, (int) (System.currentTimeMillis() & 0xFFFF), piIntent,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);

        NotificationCompat.Builder n = new NotificationCompat.Builder(ctx, CyberShieldApp.CHANNEL_ALERTS)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle("Suspicious SMS (" + priority + ")")
                .setContentText(Redact.snippet(summary))
                .setStyle(new NotificationCompat.BigTextStyle().bigText(Redact.snippet(summary)))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(true)
                .setContentIntent(pi);

        NotificationManager nm = ctx.getSystemService(NotificationManager.class);
        if (nm != null) nm.notify((int) (System.currentTimeMillis() & 0xFFFFFF), n.build());
    }
}
