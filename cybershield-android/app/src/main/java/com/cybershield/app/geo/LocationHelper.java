package com.cybershield.app.geo;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageManager;
import android.location.Location;
import android.os.Handler;
import android.os.Looper;

import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import com.google.android.gms.location.CurrentLocationRequest;
import com.google.android.gms.location.FusedLocationProviderClient;
import com.google.android.gms.location.LocationServices;
import com.google.android.gms.location.Priority;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * One-shot device geolocation for tagging fraud incident reports with the
 * reporter's real GPS position (feeds the backend's cyber-crime jurisdiction
 * routing at POST /api/v1/forensics/incident-report).
 *
 * Deliberately foreground-only (no ACCESS_BACKGROUND_LOCATION, no persistent
 * tracking service): the SIH26106 requirement is geo-tagging a reported
 * incident, not continuous surveillance of the user.
 */
public final class LocationHelper {

    public interface Callback {
        void onLocation(double lat, double lon, float accuracyMeters, String provider);
        void onUnavailable(String reason);
    }

    private static final long TIMEOUT_MS = 8000L;

    private LocationHelper() {}

    public static boolean hasPermission(Context ctx) {
        return ContextCompat.checkSelfPermission(ctx, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
                || ContextCompat.checkSelfPermission(ctx, Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED;
    }

    public static void requestPermission(Activity activity, int requestCode) {
        ActivityCompat.requestPermissions(activity, new String[]{
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.ACCESS_COARSE_LOCATION
        }, requestCode);
    }

    /** Fetches a fresh fix; falls back to the last-known fix; times out gracefully. */
    public static void fetchCurrentLocation(Context ctx, Callback cb) {
        if (!hasPermission(ctx)) {
            cb.onUnavailable("Location permission not granted");
            return;
        }

        FusedLocationProviderClient client = LocationServices.getFusedLocationProviderClient(ctx);
        AtomicBoolean done = new AtomicBoolean(false);
        Handler main = new Handler(Looper.getMainLooper());

        Runnable timeoutFallback = () -> {
            if (done.compareAndSet(false, true)) {
                fallbackToLastKnown(client, cb);
            }
        };
        main.postDelayed(timeoutFallback, TIMEOUT_MS);

        try {
            CurrentLocationRequest request = new CurrentLocationRequest.Builder()
                    .setPriority(Priority.PRIORITY_BALANCED_POWER_ACCURACY)
                    .setMaxUpdateAgeMillis(60_000L)
                    .build();

            client.getCurrentLocation(request, null)
                    .addOnSuccessListener(location -> {
                        if (done.compareAndSet(false, true)) {
                            main.removeCallbacks(timeoutFallback);
                            if (location != null) {
                                cb.onLocation(location.getLatitude(), location.getLongitude(),
                                        location.getAccuracy(), providerLabel(location));
                            } else {
                                fallbackToLastKnown(client, cb);
                            }
                        }
                    })
                    .addOnFailureListener(e -> {
                        if (done.compareAndSet(false, true)) {
                            main.removeCallbacks(timeoutFallback);
                            fallbackToLastKnown(client, cb);
                        }
                    });
        } catch (SecurityException e) {
            if (done.compareAndSet(false, true)) {
                main.removeCallbacks(timeoutFallback);
                cb.onUnavailable("Location permission revoked");
            }
        }
    }

    private static void fallbackToLastKnown(FusedLocationProviderClient client, Callback cb) {
        try {
            client.getLastLocation()
                    .addOnSuccessListener(location -> {
                        if (location != null) {
                            cb.onLocation(location.getLatitude(), location.getLongitude(),
                                    location.getAccuracy(), providerLabel(location));
                        } else {
                            cb.onUnavailable("No GPS fix available (indoors / GPS off)");
                        }
                    })
                    .addOnFailureListener(e -> cb.onUnavailable("Location lookup failed: " + e.getMessage()));
        } catch (SecurityException e) {
            cb.onUnavailable("Location permission revoked");
        }
    }

    private static String providerLabel(Location location) {
        String p = location.getProvider();
        return p != null ? p : "fused";
    }
}
