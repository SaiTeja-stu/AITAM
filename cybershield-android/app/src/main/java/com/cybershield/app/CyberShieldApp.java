package com.cybershield.app;

import android.app.Application;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.os.Build;

import com.cybershield.app.data.AppDatabase;
import com.cybershield.app.net.ApiModule;

/** Process-wide singletons: Retrofit API and the Room database. */
public class CyberShieldApp extends Application {

    public static final String CHANNEL_ALERTS = "cybershield.alerts";

    private static CyberShieldApp instance;
    private AppDatabase db;
    private ApiModule api;

    public static CyberShieldApp get() {
        return instance;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        instance = this;
        db = AppDatabase.create(this);
        api = new ApiModule(this);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ALERTS, "Fraud alerts", NotificationManager.IMPORTANCE_HIGH);
            ch.setDescription("Warnings about suspicious payments, links and messages");
            getSystemService(NotificationManager.class).createNotificationChannel(ch);
        }
    }

    public AppDatabase db() {
        return db;
    }

    public ApiModule api() {
        return api;
    }
}
