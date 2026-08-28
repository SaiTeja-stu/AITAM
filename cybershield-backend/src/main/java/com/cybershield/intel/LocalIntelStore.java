package com.cybershield.intel;

import com.cybershield.report.ThreatReportRepository;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory threat intelligence: curated blocklists / allowlists shipped with
 * the app plus community-reported indicators from the database. All lookups are
 * O(1). This stands in for live feeds (Safe Browsing, PhishTank, URLhaus) which
 * plug in behind the same interface.
 */
@Component
public class LocalIntelStore {

    private static final Logger log = LoggerFactory.getLogger(LocalIntelStore.class);

    private final ThreatReportRepository reports;

    private final Set<String> blockedDomains = ConcurrentHashMap.newKeySet();
    private final Set<String> allowedDomains = ConcurrentHashMap.newKeySet();
    private final Set<String> shorteners = ConcurrentHashMap.newKeySet();
    private final Set<String> suspiciousTlds = ConcurrentHashMap.newKeySet();
    private final Set<String> knownBrands = ConcurrentHashMap.newKeySet();
    private final Set<String> reportedDomains = ConcurrentHashMap.newKeySet();
    private final Set<String> reportedVpaHashes = ConcurrentHashMap.newKeySet();

    public LocalIntelStore(ThreatReportRepository reports) {
        this.reports = reports;
    }

    @PostConstruct
    void load() {
        loadInto("intel/blocklist-domains.txt", blockedDomains);
        loadInto("intel/allowlist-domains.txt", allowedDomains);
        loadInto("intel/shorteners.txt", shorteners);
        loadInto("intel/suspicious-tlds.txt", suspiciousTlds);
        loadInto("intel/brands.txt", knownBrands);
        refreshCommunity();
        log.info("Intel loaded: {} blocked, {} allowed, {} brands, {} shorteners",
                blockedDomains.size(), allowedDomains.size(), knownBrands.size(), shorteners.size());
    }

    /** Re-pull community indicators from the DB (called after a new report). */
    public void refreshCommunity() {
        try {
            reportedDomains.clear();
            reportedVpaHashes.clear();
            reports.findConfirmedIndicators().forEach(row -> {
                if (row.getIndicatorType() == IndicatorType.DOMAIN && row.getIndicatorValue() != null) {
                    reportedDomains.add(row.getIndicatorValue().toLowerCase(Locale.ROOT));
                } else if (row.getIndicatorType() == IndicatorType.VPA_HASH && row.getIndicatorValue() != null) {
                    reportedVpaHashes.add(row.getIndicatorValue());
                }
            });
        } catch (RuntimeException e) {
            log.debug("community refresh skipped: {}", e.toString());
        }
    }

    private void loadInto(String path, Set<String> target) {
        try {
            ClassPathResource res = new ClassPathResource(path);
            if (!res.exists()) return;
            try (InputStream in = res.getInputStream();
                 BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    String v = line.trim().toLowerCase(Locale.ROOT);
                    if (v.isEmpty() || v.startsWith("#")) continue;
                    target.add(v);
                }
            }
        } catch (Exception e) {
            log.warn("could not load intel file {}: {}", path, e.toString());
        }
    }

    // --- lookups ---

    public boolean isBlockedDomain(String host) {
        return host != null && (matchesHostOrParent(host, blockedDomains) || matchesHostOrParent(host, reportedDomains));
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
        return new HashSet<>(knownBrands);
    }

    public boolean isReportedVpaHash(String hash) {
        return hash != null && reportedVpaHashes.contains(hash);
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
