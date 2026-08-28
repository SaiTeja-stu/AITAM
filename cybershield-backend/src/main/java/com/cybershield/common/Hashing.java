package com.cybershield.common;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

/**
 * Keyed hashing for privacy-preserving indicators (trust policy T-03).
 * VPAs, phone numbers and raw content are stored/compared only as HMAC-SHA-256
 * digests so the database never holds the plaintext.
 */
@Component
public class Hashing {

    private final byte[] key;

    public Hashing(@Value("${cybershield.hmac-secret:dev-only-insecure-salt-change-me}") String secret) {
        this.key = secret.getBytes(StandardCharsets.UTF_8);
    }

    public String hmac(String value) {
        if (value == null) return null;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            byte[] out = mac.doFinal(value.trim().toLowerCase().getBytes(StandardCharsets.UTF_8));
            return "h:" + HexFormat.of().formatHex(out);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC unavailable", e);
        }
    }

    public String sha256(String value) {
        if (value == null) return null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] out = md.digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(out);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
