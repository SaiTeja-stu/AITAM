package com.cybershield.intel;

import android.content.Context;

import com.cybershield.app.data.AppDatabase;
import com.cybershield.app.data.BlockedIndicator;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * On-device threat intelligence for the ported detection engine.
 *
 * <p>Curated lists ship as text files in {@code assets/intel/}. Community
 * indicators (confirmed reports, fraudulent VPAs) come from the Room
 * {@code blocked} table, which the app syncs from the backend when one is
 * reachable — but the engine works fully offline without it.
 */
public final class LocalIntelStore {

    private final Set<String> blockedDomains = new HashSet<>();
    private final Set<String> allowedDomains = new HashSet<>();
    private final Set<String> shorteners = new HashSet<>();
    private final Set<String> suspiciousTlds = new HashSet<>();
    private final Set<String> knownBrands = new HashSet<>();

    private final AppDatabase db;

    public LocalIntelStore(Context ctx) {
        this.db = AppDatabase.get(ctx);
        load(ctx, "intel/blocklist-domains.txt", blockedDomains);
        load(ctx, "intel/allowlist-domains.txt", allowedDomains);
        load(ctx, "intel/shorteners.txt", shorteners);
        load(ctx, "intel/suspicious-tlds.txt", suspiciousTlds);
        load(ctx, "intel/brands.txt", knownBrands);
    }

    private void load(Context ctx, String assetPath, Set<String> target) {
        try (InputStream in = ctx.getAssets().open(assetPath);
             BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                String v = line.trim().toLowerCase(Locale.ROOT);
                if (v.isEmpty() || v.startsWith("#")) continue;
                target.add(v);
            }
        } catch (Exception ignored) {
            // a missing list just means that category of check is inert
        }
    }

    // --- lookups -----------------------------------------------------------

    public boolean isBlockedDomain(String host) {
        if (host == null) return false;
        if (matchesHostOrParent(host, blockedDomains)) return true;
        try {
            return db.blocklistDao().isBlocked(BlockedIndicator.TYPE_DOMAIN, host.toLowerCase(Locale.ROOT));
        } catch (RuntimeException e) {
            return false;
        }
    }

    public boolean isAllowedDomain(String host) {
        return host != null && matchesHostOrParent(host, allowedDomains);
    }

    public boolean isShortener(String host) {
        return host != null && matchesHostOrParent(host, shorteners);
    }

    public boolean isSuspiciousTld(String host) {
        if (host == null) return false;
        int dot = host.lastIndexOf('.');
        if (dot < 0) return false;
        return suspiciousTlds.contains(host.substring(dot + 1).toLowerCase(Locale.ROOT));
    }

    public Set<String> knownBrands() {
        return Collections.unmodifiableSet(knownBrands);
    }

    /** {@code hash} is the {@code h:<hex>} HMAC form the backend and app both use for VPAs. */
    public boolean isReportedVpaHash(String hash) {
        if (hash == null) return false;
        try {
            return db.blocklistDao().isBlocked(BlockedIndicator.TYPE_VPA, hash);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private boolean matchesHostOrParent(String host, Set<String> set) {
        String h = host.toLowerCase(Locale.ROOT);
        while (true) {
            if (set.contains(h)) return true;
            int dot = h.indexOf('.');
            if (dot < 0) return false;
            h = h.substring(dot + 1);
            if (!h.contains(".")) return set.contains(h);
        }
    }
}
