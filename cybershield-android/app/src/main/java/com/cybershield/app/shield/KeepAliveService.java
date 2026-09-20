package com.cybershield.app.shield;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;

import androidx.core.app.NotificationCompat;

import com.cybershield.app.R;
import com.cybershield.app.ui.MainActivity;

/**
 * A quiet, always-on foreground service that shows one small "protection is on" notification.
 *
 * <p>Why: phone makers (Oppo / Realme / Xiaomi ...) kill background apps aggressively. A process that hosts
 * a foreground service is ranked far higher, so the browsing shield and SMS checks keep running after the
 * user closes the app or clears Recents. Started from the accessibility service when it connects.
 */
public class KeepAliveService extends Service {

    private static final String CHANNEL = "cybershield.protection";
    private static final int ID = 7;

    public static void start(Context ctx) {
        try {
            Intent i = new Intent(ctx, KeepAliveService.class);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) ctx.startForegroundService(i);
            else ctx.startService(i);
        } catch (Throwable ignored) {
            // never crash the shield because of the keep-alive
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && nm != null) {
            NotificationChannel ch = new NotificationChannel(CHANNEL, "Protection status",
                    NotificationManager.IMPORTANCE_MIN);
            ch.setDescription("Shows that Secure Me protection is running");
            ch.setShowBadge(false);
            nm.createNotificationChannel(ch);
        }
        PendingIntent open = PendingIntent.getActivity(this, 0,
                new Intent(this, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Notification n = new NotificationCompat.Builder(this, CHANNEL)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle("Secure Me protection is on")
                .setContentText("Watching links, messages and payments")
                .setPriority(NotificationCompat.PRIORITY_MIN)
                .setOngoing(true)
                .setShowWhen(false)
                .setContentIntent(open)
                .build();
        startForeground(ID, n);
        return START_STICKY;   // the system restarts it if it is ever killed
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
