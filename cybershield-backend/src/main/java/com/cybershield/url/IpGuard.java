package com.cybershield.url;

import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Locale;

/**
 * SSRF defence: decides whether a resolved IP address is safe to connect to.
 * Blocks loopback, private, link-local, CGNAT, ULA, unspecified, multicast and
 * cloud metadata addresses. Also normalises alternate textual IP representations
 * (decimal / octal / hex) before evaluation.
 */
@Component
public class IpGuard {

    /** Cloud metadata endpoints that must never be reachable. */
    private static final String[] METADATA_HOSTS = {
            "169.254.169.254",           // AWS / GCP / Azure / DO / OpenStack
            "100.100.100.200",           // Alibaba Cloud
            "metadata.google.internal",
            "metadata.goog"
    };

    /** True if this hostname string is a literal metadata address/name. */
    public boolean isMetadataHostname(String host) {
        if (host == null) return false;
        String h = host.toLowerCase(Locale.ROOT).trim();
        for (String m : METADATA_HOSTS) {
            if (h.equals(m)) return true;
        }
        return false;
    }

    /**
     * Normalise a host that may be an alternate IPv4 representation
     * (e.g. "2130706433", "0x7f.1", "017700000001") to dotted-quad.
     * Returns the input unchanged if it is not a recognised numeric form.
     */
    public String normalizeNumericHost(String host) {
        if (host == null || host.isBlank()) return host;
        String h = host.trim();
        if (h.matches("^\\d{1,3}(\\.\\d{1,3}){3}$")) return h; // already dotted-quad

        try {
            // Single decimal / hex / octal integer form
            if (h.matches("^(0x[0-9a-fA-F]+|0[0-7]*|\\d+)$")) {
                long value = parseRadix(h);
                if (value >= 0 && value <= 0xFFFFFFFFL) {
                    return String.format("%d.%d.%d.%d",
                            (value >> 24) & 0xFF, (value >> 16) & 0xFF,
                            (value >> 8) & 0xFF, value & 0xFF);
                }
            }
            // Dotted form with hex/octal parts, possibly < 4 parts
            if (h.matches("^(0x[0-9a-fA-F]+|0[0-7]*|\\d+)(\\.(0x[0-9a-fA-F]+|0[0-7]*|\\d+)){1,3}$")) {
                String[] parts = h.split("\\.");
                long[] nums = new long[parts.length];
                for (int i = 0; i < parts.length; i++) nums[i] = parseRadix(parts[i]);
                long value;
                switch (parts.length) {
                    case 2 -> value = (nums[0] << 24) | (nums[1] & 0xFFFFFF);
                    case 3 -> value = (nums[0] << 24) | (nums[1] << 16) | (nums[2] & 0xFFFF);
                    default -> value = (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3];
                }
                if (value >= 0 && value <= 0xFFFFFFFFL) {
                    return String.format("%d.%d.%d.%d",
                            (value >> 24) & 0xFF, (value >> 16) & 0xFF,
                            (value >> 8) & 0xFF, value & 0xFF);
                }
            }
        } catch (RuntimeException ignored) {
            // fall through
        }
        return h;
    }

    private long parseRadix(String p) {
        if (p.startsWith("0x") || p.startsWith("0X")) return Long.parseLong(p.substring(2), 16);
        if (p.length() > 1 && p.startsWith("0")) return Long.parseLong(p, 8);
        return Long.parseLong(p);
    }

    /** Core check: is it unsafe to open a connection to this resolved address? */
    public boolean isBlocked(InetAddress addr) {
        if (addr == null) return true;
        if (addr.isAnyLocalAddress()      // 0.0.0.0 / ::
                || addr.isLoopbackAddress()   // 127.0.0.0/8, ::1
                || addr.isLinkLocalAddress()  // 169.254/16, fe80::/10
                || addr.isSiteLocalAddress()  // 10/8, 172.16/12, 192.168/16
                || addr.isMulticastAddress()) {
            return true;
        }
        byte[] b = addr.getAddress();
        if (addr instanceof Inet4Address) {
            int o0 = b[0] & 0xFF, o1 = b[1] & 0xFF;
            if (o0 == 100 && o1 >= 64 && o1 <= 127) return true;  // 100.64/10 CGNAT
            if (o0 == 192 && o1 == 0 && (b[2] & 0xFF) == 0) return true; // 192.0.0/24
            if (o0 == 198 && (o1 == 18 || o1 == 19)) return true; // 198.18/15 benchmarking
            if (o0 == 169 && o1 == 254) return true;              // metadata (defensive)
            if (o0 == 0) return true;                              // 0.0.0.0/8
        } else if (addr instanceof Inet6Address) {
            int first = b[0] & 0xFF;
            if ((first & 0xFE) == 0xFC) return true;               // fc00::/7 ULA
            // IPv4-mapped ::ffff:0:0/96 -> re-check embedded v4
            if (isV4Mapped(b)) {
                byte[] v4 = new byte[]{b[12], b[13], b[14], b[15]};
                try {
                    return isBlocked(InetAddress.getByAddress(v4));
                } catch (Exception e) {
                    return true;
                }
            }
            BigInteger v = new BigInteger(1, b);
            if (v.equals(BigInteger.ZERO)) return true;            // ::
        }
        return false;
    }

    private boolean isV4Mapped(byte[] b) {
        for (int i = 0; i < 10; i++) if (b[i] != 0) return false;
        return (b[10] & 0xFF) == 0xFF && (b[11] & 0xFF) == 0xFF;
    }
}
