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

    public long lastActionAt() {
        return p.getLong("last_action_at", 0L);
    }

    public void markAction() {
        p.edit().putLong("last_action_at", System.currentTimeMillis()).apply();
    }
}
