package com.cybershield.app.mailwatch;

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.os.Bundle;
import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;
import android.text.TextUtils;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import com.cybershield.app.CyberShieldApp;
import com.cybershield.app.R;
import com.cybershield.app.net.dto.AnalyzeResponse;
import com.cybershield.app.shield.ShieldPrefs;
import com.cybershield.app.ui.VerdictActivity;
import com.cybershield.app.util.Redact;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Auto-scans incoming email by reading the mail app's own new-message
 * notification — sender, subject and preview line. No Gmail login, no OAuth,
 * nothing uploaded: the text is run through the same on-device EMAIL engine as
 * a manual paste, and if it looks like phishing Secure Me posts its own
 * warning notification.
 *
 * <p>Limitation: a notification only carries the sender name, subject and a
 * ~100-char preview — not the full body or the SPF/DKIM/DMARC headers. It still
 * catches look-alike senders, urgency/credential language and bad links. For the
 * full check, open the mail and Share it into Secure Me.
 */
public class EmailNotificationListener extends NotificationListenerService {

    private static final String TAG = "CSMailWatch";

    private static final Set<String> MAIL_PACKAGES = new HashSet<>(Arrays.asList(
            "com.google.android.gm",                       // Gmail
            "com.google.android.apps.inbox",
            "com.microsoft.office.outlook",
            "com.yahoo.mobile.client.android.mail",
            "com.samsung.android.email.provider",
            "com.samsung.android.email.ui",
            "ch.protonmail.android",
            "me.bluemail.mail",
            "com.fsck.k9",
            "ru.yandex.mail",
            "com.my.mail",
            "com.readdle.spark"));

    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private ShieldPrefs prefs;

    private String lastKey = "";
    private long lastAt = 0;

    @Override
    public void onListenerConnected() {
        prefs = new ShieldPrefs(this);
        Log.i(TAG, "email watch connected");
    }

    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        try {
            if (sbn == null) return;
            if (prefs == null) prefs = new ShieldPrefs(this);
            if (!prefs.watchEmail()) return;
            boolean testInjection = com.cybershield.app.BuildConfig.DEBUG
                    && "com.android.shell".equals(sbn.getPackageName());
            if (!testInjection && !MAIL_PACKAGES.contains(sbn.getPackageName())) return;

            Notification n = sbn.getNotification();
            if (n == null) return;
            if ((n.flags & Notification.FLAG_GROUP_SUMMARY) != 0) return;   // the "3 new emails" roll-up

            Bundle x = n.extras;
            if (x == null) return;
            String sender = str(x.getCharSequence(Notification.EXTRA_TITLE));
            String subject = str(x.getCharSequence(Notification.EXTRA_TEXT));
            String preview = str(x.getCharSequence(Notification.EXTRA_BIG_TEXT));
            if (preview.isEmpty()) {
                CharSequence[] lines = x.getCharSequenceArray(Notification.EXTRA_TEXT_LINES);
                if (lines != null && lines.length > 0) preview = str(lines[lines.length - 1]);
            }
            if (sender.isEmpty() && subject.isEmpty() && preview.isEmpty()) return;

            String key = sbn.getKey() + "|" + subject.hashCode();
            long now = System.currentTimeMillis();
            if (key.equals(lastKey) && now - lastAt < 60_000) return;
            lastKey = key;
            lastAt = now;

            // reconstruct a minimal email for the engine
            final String pseudo = "From: " + sender + "\nSubject: " + subject + "\n\n"
                    + (preview.isEmpty() ? subject : preview);

            io.execute(() -> {
                try {
                    AnalyzeResponse v = CyberShieldApp.get().analyzer().analyze("EMAIL", pseudo, null);
                    Log.i(TAG, "mail from '" + sender + "' -> " + v.riskLevel + " " + v.riskScore);
                    if ("MALICIOUS".equals(v.riskLevel) || "HIGH_RISK".equals(v.riskLevel)
                            || "SUSPICIOUS".equals(v.riskLevel)) {
                        warn(sender, pseudo, v);
                    }
                } catch (Throwable ignored) {
                    // never crash the mail app's notification path
                }
            });
        } catch (Throwable t) {
            Log.w(TAG, "onNotificationPosted failed", t);
        }
    }

    private void warn(String sender, String pseudo, AnalyzeResponse v) {
        String reason = "This email looks like a scam.";
        for (AnalyzeResponse.Signal s : v.signals) {
            if (s.weight > 0) { reason = s.name + " — " + s.detail; break; }
        }
        boolean bad = "MALICIOUS".equals(v.riskLevel) || "HIGH_RISK".equals(v.riskLevel);

        Intent open = VerdictActivity.intent(this, "EMAIL", pseudo, "mail-watch");
        open.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        PendingIntent pi = PendingIntent.getActivity(this, (int) (System.currentTimeMillis() & 0xFFFF),
                open, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);

        NotificationCompat.Builder nb = new NotificationCompat.Builder(this, CyberShieldApp.CHANNEL_ALERTS)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle((bad ? "⚠ Likely phishing email" : "Suspicious email") + " — " + shorten(sender))
                .setContentText(Redact.snippet(reason))
                .setStyle(new NotificationCompat.BigTextStyle().bigText(Redact.snippet(reason)))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(true)
                .setContentIntent(pi);

        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm != null) nm.notify((int) (System.currentTimeMillis() & 0xFFFFFF), nb.build());
    }

    private static String str(CharSequence c) { return c == null ? "" : c.toString().trim(); }

    private static String shorten(String s) {
        return s.length() > 40 ? s.substring(0, 40) + "…" : s;
    }
}
