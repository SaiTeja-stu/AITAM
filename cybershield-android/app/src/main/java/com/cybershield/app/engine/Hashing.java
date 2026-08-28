package com.cybershield.app.engine;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * Keyed hash for indicator matching. Must use the SAME secret as the backend
 * (cybershield.hmac-secret) so the synced blocklist of hashed VPAs lines up.
 * The value here is the dev default - inject the real one at build time.
 */
public final class Hashing {

    private static final byte[] KEY =
            "dev-only-insecure-salt-change-me".getBytes(StandardCharsets.UTF_8);

    private Hashing() {}

    public static String hmac(String value) {
        if (value == null) return null;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(KEY, "HmacSHA256"));
            byte[] out = mac.doFinal(value.trim().toLowerCase().getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder("h:");
            for (byte b : out) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "h:" + Integer.toHexString(value.hashCode());
        }
    }
}
