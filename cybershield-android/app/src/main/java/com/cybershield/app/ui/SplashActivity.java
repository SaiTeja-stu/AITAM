package com.cybershield.app.ui;

import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.view.View;
import android.view.animation.DecelerateInterpolator;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.cybershield.app.CyberShieldApp;
import com.cybershield.app.R;

import java.util.concurrent.Executors;

/**
 * Launch / loading screen. The window background (splash_bg) paints the logo
 * instantly on cold start; this screen then does the real warm-up work while the
 * brand animation plays:
 *   - builds the on-device detection engine (loads the ML URL model from assets)
 *   - refreshes the access token from the stored refresh token, if signed in
 * It holds for at least {@link #MIN_SHOW_MS} so it never just flashes, and hands
 * off no later than {@link #MAX_SHOW_MS} even if warm-up is slow. {@link MainActivity}
 * then routes to the dashboard or the sign-in screen based on the session.
 */
public class SplashActivity extends AppCompatActivity {

    private static final long MIN_SHOW_MS = 1100L;
    private static final long MAX_SHOW_MS = 4000L;

    private final Handler main = new Handler(Looper.getMainLooper());
    private long startedAt;
    private volatile boolean warmDone = false;
    private boolean handedOff = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_splash);
        startedAt = SystemClock.elapsedRealtime();

        View logo = findViewById(R.id.logo);
        View wordmark = findViewById(R.id.wordmark);
        TextView tagline = findViewById(R.id.tagline);

        int i = 0;
        for (View v : new View[]{logo, wordmark, tagline}) {
            v.setAlpha(0f);
            v.setTranslationY(24f);
            v.animate().alpha(1f).translationY(0f)
                    .setDuration(420)
                    .setStartDelay(i++ * 80L)
                    .setInterpolator(new DecelerateInterpolator())
                    .start();
        }

        warmUp(tagline);

        // Hard ceiling so a slow device still moves on.
        main.postDelayed(this::handOff, MAX_SHOW_MS);
    }

    /** Load the heavy stuff off the main thread, then try to hand off. */
    private void warmUp(TextView tagline) {
        Executors.newSingleThreadExecutor().execute(() -> {
            try {
                CyberShieldApp app = CyberShieldApp.get();
                app.analyzer();                       // forces ML model + policy load
                if (app.api().store().hasRefreshToken() && app.api().store().token() == null) {
                    main.post(() -> tagline.setText("Signing you in…"));
                    app.api().tryRefresh();            // silent token refresh
                }
            } catch (Throwable ignored) {
                // never block the app on warm-up failure
            } finally {
                warmDone = true;
                main.post(this::handOff);
            }
        });

        // If warm-up is quick, still respect the minimum show time.
        main.postDelayed(this::handOff, MIN_SHOW_MS);
    }

    private synchronized void handOff() {
        if (handedOff) return;
        long elapsed = SystemClock.elapsedRealtime() - startedAt;
        if ((!warmDone || elapsed < MIN_SHOW_MS) && elapsed < MAX_SHOW_MS) {
            main.postDelayed(this::handOff, Math.max(60, MIN_SHOW_MS - elapsed));
            return;
        }
        handedOff = true;
        startActivity(new Intent(this, MainActivity.class));
        overridePendingTransition(android.R.anim.fade_in, android.R.anim.fade_out);
        finish();
    }

    @Override
    public void onBackPressed() {
        // ignore during the loading screen
    }
}
