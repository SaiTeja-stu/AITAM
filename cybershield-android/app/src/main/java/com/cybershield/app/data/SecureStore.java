package com.cybershield.app.data;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

import com.cybershield.app.BuildConfig;

/**
 * Encrypted key/value store for the auth tokens and small auth-related flags.
 * Falls back to plain SharedPreferences only if the keystore is unavailable
 * (very old / broken devices) so the app still works.
 */
public class SecureStore {

    private static final String FILE = "cybershield_secure";
    private static final String K_ACCESS = "token";
    private static final String K_REFRESH = "refresh";
    private static final String K_EMAIL = "email";
    private static final String K_BIOMETRIC = "biometric_lock";
    private static final String K_BASE_URL = "base_url";
    private static final String K_GUEST = "offline_guest";

    private final SharedPreferences prefs;

    public SecureStore(Context ctx) {
        SharedPreferences p;
        try {
            MasterKey key = new MasterKey.Builder(ctx)
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                    .build();
            p = EncryptedSharedPreferences.create(
                    ctx, FILE, key,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM);
        } catch (Exception e) {
            p = ctx.getSharedPreferences(FILE + "_fallback", Context.MODE_PRIVATE);
        }
        this.prefs = p;
    }

    // --- access token (15 min) ---
    public String token() { return prefs.getString(K_ACCESS, null); }
    public void setToken(String t) { prefs.edit().putString(K_ACCESS, t).apply(); }
    public boolean hasToken() { return token() != null; }

    // --- refresh token (long-lived, enables fingerprint re-login) ---
    public String refreshToken() { return prefs.getString(K_REFRESH, null); }
    public void setRefreshToken(String t) { prefs.edit().putString(K_REFRESH, t).apply(); }
    public boolean hasRefreshToken() { return refreshToken() != null; }

    /** True if the app may proceed past the auth screen — a real backend session is required. */
    public boolean hasSession() { return hasToken() || hasRefreshToken(); }

    /** Kept as an alias for call sites that distinguished account vs guest. */
    public boolean hasAccount() { return hasSession(); }

    public boolean isGuest() { return false; }
    public void setGuest(boolean on) { /* guest mode removed */ }

    public void setTokens(String access, String refresh) {
        SharedPreferences.Editor e = prefs.edit();
        if (access != null) e.putString(K_ACCESS, access);
        if (refresh != null) e.putString(K_REFRESH, refresh);
        e.apply();
    }

    public void clearSession() {
        prefs.edit().remove(K_ACCESS).remove(K_REFRESH).remove(K_GUEST).apply();
    }

    // --- backend URL (editable in-app so no rebuild needed per network) ---
    public String baseUrl() {
        String u = prefs.getString(K_BASE_URL, null);
        return (u == null || u.isBlank()) ? BuildConfig.API_BASE_URL : u;
    }
    public void setBaseUrl(String u) {
        if (u == null || u.isBlank()) { prefs.edit().remove(K_BASE_URL).apply(); return; }
        String v = u.trim();
        if (!v.startsWith("http://") && !v.startsWith("https://")) v = "http://" + v;
        if (!v.endsWith("/")) v = v + "/";
        prefs.edit().putString(K_BASE_URL, v).apply();
    }

    // --- misc ---
    public String email() { return prefs.getString(K_EMAIL, null); }
    public void setEmail(String e) { prefs.edit().putString(K_EMAIL, e).apply(); }

    /** Off by default - the user opts in from settings. */
    public boolean biometricLock() { return prefs.getBoolean(K_BIOMETRIC, false); }
    public void setBiometricLock(boolean on) { prefs.edit().putBoolean(K_BIOMETRIC, on).apply(); }

    /** Language for the education section: "en" | "te" | "hi". */
    public String eduLang() { return prefs.getString("edu_lang", "en"); }
    public void setEduLang(String lang) { prefs.edit().putString("edu_lang", lang).apply(); }
}
