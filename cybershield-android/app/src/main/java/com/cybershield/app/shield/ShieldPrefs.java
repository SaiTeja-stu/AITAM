package com.cybershield.app.shield;

import android.content.Context;
import android.content.SharedPreferences;

/** Small settings store for the shield (user can disable it, tune strictness). */
public class ShieldPrefs {

    private static final String FILE = "shield_prefs";
    private final SharedPreferences p;

    public ShieldPrefs(Context ctx) {
        this.p = ctx.getSharedPreferences(FILE, Context.MODE_PRIVATE);
    }

    public boolean isEnabled() {
        return p.getBoolean("enabled", true);
    }

    public void setEnabled(boolean v) {
        p.edit().putBoolean("enabled", v).apply();
    }

    /** When true, only warn (never auto-press Back). */
    public boolean warnOnly() {
        return p.getBoolean("warn_only", false);
    }

    /** Watch the address bar in browsers and warn on dangerous sites. Opt-in. */
    public boolean watchBrowsers() {
        return p.getBoolean("watch_browsers", true);
    }

    public void setWatchBrowsers(boolean v) {
        p.edit().putBoolean("watch_browsers", v).apply();
    }

    /**
     * Strict browsing: also hard-block HIGH_RISK sites (press Back), and show a
     * dismissible caution card for sites we could not verify. Default off — most
     * of the web is legitimately "unverified".
     */
    public boolean strictMode() {
        return p.getBoolean("strict_mode", false);
    }

    public void setStrictMode(boolean v) {
        p.edit().putBoolean("strict_mode", v).apply();
    }

    /** Auto-scan email by reading the mail app's new-message notifications. */
    public boolean watchEmail() {
        return p.getBoolean("watch_email", true);
    }

    public void setWatchEmail(boolean v) {
        p.edit().putBoolean("watch_email", v).apply();
    }

    /** Running count of scam SMS Cyber Shield has flagged (shown on the alert). */
    public int spamSmsCount() {
        return p.getInt("spam_sms_count", 0);
    }

    public int bumpSpamSmsCount() {
        int n = spamSmsCount() + 1;
        p.edit().putInt("spam_sms_count", n).apply();
        return n;
    }

    public long lastActionAt() {
        return p.getLong("last_action_at", 0L);
    }

    public void markAction() {
        p.edit().putLong("last_action_at", System.currentTimeMillis()).apply();
    }
}
