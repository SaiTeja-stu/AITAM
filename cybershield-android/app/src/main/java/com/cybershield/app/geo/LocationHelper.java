package com.cybershield.app.geo;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageManager;
import android.location.Location;
import android.location.LocationManager;
import android.os.Build;
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
 * Keeps reporter GPS strictly separate from email relay transit geolocation.
 * Rejects (0,0) Null Island coordinates as valid positions.
 * Distinguishes precise vs approximate permission and labels stale last-known fixes.
 * Deliberately foreground-only (no background tracking or persistent surveillance).
 */
public final class LocationHelper {

    public interface Callback {
        void onLocation(Double lat, Double lon, Float accuracyMeters, String providerInfo);
        void onUnavailable(String reason);
    }

    private static final long CURRENT_FIX_TIMEOUT_MS = 8000L;
    private static final long MAX_STALE_AGE_MS = 15 * 60 * 1000L; // 15 minutes

    private LocationHelper() {}

    public static boolean hasPermission(Context ctx) {
        return ContextCompat.checkSelfPermission(ctx, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
                || ContextCompat.checkSelfPermission(ctx, Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED;
    }

    public static boolean isFineLocationGranted(Context ctx) {
        return ContextCompat.checkSelfPermission(ctx, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED;
    }

    public static boolean isLocationServiceEnabled(Context ctx) {
        LocationManager lm = (LocationManager) ctx.getSystemService(Context.LOCATION_SERVICE);
        if (lm == null) return false;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            return lm.isLocationEnabled();
        } else {
            return lm.isProviderEnabled(LocationManager.GPS_PROVIDER)
                    || lm.isProviderEnabled(LocationManager.NETWORK_PROVIDER);
        }
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

        if (!isLocationServiceEnabled(ctx)) {
            cb.onUnavailable("Location services are disabled in device settings");
            return;
        }

        FusedLocationProviderClient client = LocationServices.getFusedLocationProviderClient(ctx);
        AtomicBoolean done = new AtomicBoolean(false);
        Handler main = new Handler(Looper.getMainLooper());

        Runnable timeoutFallback = () -> {
            if (done.compareAndSet(false, true)) {
                fallbackToLastKnown(ctx, client, cb);
            }
        };
        main.postDelayed(timeoutFallback, CURRENT_FIX_TIMEOUT_MS);

        try {
            int priority = isFineLocationGranted(ctx)
                    ? Priority.PRIORITY_HIGH_ACCURACY
                    : Priority.PRIORITY_BALANCED_POWER_ACCURACY;

            CurrentLocationRequest request = new CurrentLocationRequest.Builder()
                    .setPriority(priority)
                    .setMaxUpdateAgeMillis(60_000L)
                    .build();

            client.getCurrentLocation(request, null)
                    .addOnSuccessListener(location -> {
                        if (done.compareAndSet(false, true)) {
                            main.removeCallbacks(timeoutFallback);
                            if (location != null && isValidCoordinate(location)) {
                                cb.onLocation(location.getLatitude(), location.getLongitude(),
                                        location.getAccuracy(), formatProvider(ctx, location, false));
                            } else {
                                fallbackToLastKnown(ctx, client, cb);
                            }
                        }
                    })
                    .addOnFailureListener(e -> {
                        if (done.compareAndSet(false, true)) {
                            main.removeCallbacks(timeoutFallback);
                            fallbackToLastKnown(ctx, client, cb);
                        }
                    });
        } catch (SecurityException e) {
            if (done.compareAndSet(false, true)) {
                main.removeCallbacks(timeoutFallback);
                cb.onUnavailable("Location permission revoked");
            }
        }
    }

    private static void fallbackToLastKnown(Context ctx, FusedLocationProviderClient client, Callback cb) {
        try {
            client.getLastLocation()
                    .addOnSuccessListener(location -> {
                        if (location != null && isValidCoordinate(location)) {
                            long age = System.currentTimeMillis() - location.getTime();
                            boolean stale = age > MAX_STALE_AGE_MS;
                            cb.onLocation(location.getLatitude(), location.getLongitude(),
                                    location.getAccuracy(), formatProvider(ctx, location, stale));
                        } else {
                            cb.onUnavailable("No GPS fix available (indoors / awaiting satellite signal)");
                        }
                    })
                    .addOnFailureListener(e -> cb.onUnavailable("Location lookup failed: " + e.getMessage()));
        } catch (SecurityException e) {
            cb.onUnavailable("Location permission revoked");
        }
    }

    private static boolean isValidCoordinate(Location l) {
        // Reject Null Island (0.0, 0.0) and unphysical values
        return Math.abs(l.getLatitude()) > 0.0001 || Math.abs(l.getLongitude()) > 0.0001;
    }

    private static String formatProvider(Context ctx, Location l, boolean isStale) {
        StringBuilder sb = new StringBuilder();
        if (isFineLocationGranted(ctx)) {
            sb.append("GPS (Precise)");
        } else {
            sb.append("Network (Approximate)");
        }
        if (isStale) {
            long mins = Math.max(1, (System.currentTimeMillis() - l.getTime()) / 60000L);
            sb.append(" [Stale fix ~").append(mins).append("m ago]");
        }
        return sb.toString();
    }
}
