package com.cybershield.app.shield;

import android.app.Notification;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.PixelFormat;
import android.os.Build;
import android.os.IBinder;
import android.provider.Settings;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.TextView;

import androidx.core.app.NotificationCompat;

import com.cybershield.app.CyberShieldApp;
import com.cybershield.app.R;

/**
 * Draws the blocking warning banner over whatever app is in the foreground.
 * Runs as a short-lived foreground service (required for an overlay started
 * from the background on modern Android).
 */
public class OverlayService extends Service {

    public static final String EX_TITLE = "title";
    public static final String EX_BODY = "body";
    public static final String EX_SCORE = "score";
    public static final String EX_HARD = "hard";
    public static final String EX_HOST = "host";
    public static final String EX_PKG = "pkg";
    public static final String EX_URL = "url";

    private WindowManager wm;
    private View overlay;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startForeground(42, buildNotification());

        if (intent == null || !Settings.canDrawOverlays(this)) {
            stopSelf();
            return START_NOT_STICKY;
        }
        removeOverlay();
        show(
                intent.getStringExtra(EX_TITLE),
                intent.getStringExtra(EX_BODY),
                intent.getIntExtra(EX_SCORE, 0),
                intent.getBooleanExtra(EX_HARD, false),
                intent.getStringExtra(EX_HOST),
                intent.getStringExtra(EX_PKG),
                intent.getStringExtra(EX_URL));
        return START_NOT_STICKY;
    }

    private void show(String title, String body, int score, boolean hard, String host, String pkg, String url) {
        wm = (WindowManager) getSystemService(WINDOW_SERVICE);
        overlay = LayoutInflater.from(this).inflate(R.layout.overlay_warning, null);

        ((TextView) overlay.findViewById(R.id.ovTitle)).setText(title);
        ((TextView) overlay.findViewById(R.id.ovBody)).setText(body);
        TextView scoreView = overlay.findViewById(R.id.ovScore);
        scoreView.setText("Risk " + score + "/100");
        scoreView.setTextColor(score >= 75 ? Color.parseColor("#E5484D") : Color.parseColor("#F08A3C"));

        Button dismiss = overlay.findViewById(R.id.ovDismiss);
        Button proceed = overlay.findViewById(R.id.ovProceed);
        dismiss.setOnClickListener(v -> {
            removeOverlay();
            stopSelf();
            // hard block already replaced the page when the warning appeared; a soft warning does it now
            if (!hard) FraudAccessibilityService.leaveSite(pkg);
        });

        // Even on a dangerous site the user may continue with their own consent, but only after confirming with
        // their fingerprint / face / PIN. That confirmation is what lets Secure Me report it to the dashboard.
        proceed.setVisibility(View.VISIBLE);
        proceed.setText("I understand the risk, continue");
        proceed.setOnClickListener(v -> {
            proceed.setEnabled(false);
            Intent gate = new Intent(this, com.cybershield.app.ui.ProceedGateActivity.class)
                    .putExtra(EX_HOST, host)
                    .putExtra(EX_PKG, pkg)
                    .putExtra(EX_URL, url)
                    .putExtra(EX_SCORE, score)
                    .putExtra(EX_HARD, hard)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_NO_ANIMATION);
            startActivity(gate);
            proceed.postDelayed(() -> proceed.setEnabled(true), 2500);   // allow another try if it was cancelled
        });

        int type = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
                : WindowManager.LayoutParams.TYPE_PHONE;

        WindowManager.LayoutParams lp = new WindowManager.LayoutParams(
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.MATCH_PARENT,
                type,
                WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
                PixelFormat.TRANSLUCENT);
        lp.gravity = Gravity.CENTER;

        wm.addView(overlay, lp);
    }

    private void removeOverlay() {
        if (wm != null && overlay != null) {
            try { wm.removeView(overlay); } catch (IllegalArgumentException ignored) { }
            overlay = null;
        }
    }

    private Notification buildNotification() {
        NotificationCompat.Builder b = new NotificationCompat.Builder(this, CyberShieldApp.CHANNEL_ALERTS)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle("Secure Me is checking a payment")
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .setOngoing(true);
        return b.build();
    }

    @Override
    public void onDestroy() {
        removeOverlay();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    public static boolean canOverlay(Context ctx) {
        return Settings.canDrawOverlays(ctx);
    }
}
