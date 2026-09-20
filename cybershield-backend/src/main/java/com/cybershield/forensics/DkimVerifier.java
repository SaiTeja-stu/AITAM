package com.cybershield.forensics;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Real RFC 6376 DKIM signature verification: fetches the signer's public key
 * from DNS (the "<selector>._domainkey.<domain>" TXT record) and cryptographically
 * verifies the DKIM-Signature against the message — it does not merely check that
 * a signature header is present.
 *
 * Supports the common case: rsa-sha256 with relaxed/relaxed canonicalization
 * (the default emitted by Gmail, Outlook, SES, SendGrid and most senders). Any
 * other algorithm/canonicalization combination is reported as UNSUPPORTED
 * rather than silently claimed as verified.
 */
@Service
public class DkimVerifier {

    private static final Logger log = LoggerFactory.getLogger(DkimVerifier.class);

    public record DkimResult(String verdict, String selector, String domain, String details) {
        static DkimResult of(String verdict, String selector, String domain, String details) {
            return new DkimResult(verdict, selector, domain, details);
        }
    }

    /**
     * @param rawHeaderSection the full, unfolded raw header block (before parsing into a map)
     * @param dkimSignatureHeaderValue the raw value of the DKIM-Signature header (after "DKIM-Signature:")
     * @param bodySection the raw message body (post blank-line)
     */
    public DkimResult verify(String rawHeaderSection, String dkimSignatureHeaderValue, String bodySection) {
        if (dkimSignatureHeaderValue == null || dkimSignatureHeaderValue.isBlank()) {
            return DkimResult.of("NONE", null, null, "No DKIM-Signature header present");
        }
        try {
            Map<String, String> tags = parseTags(dkimSignatureHeaderValue);
            String algo = tags.getOrDefault("a", "");
            String canon = tags.getOrDefault("c", "simple/simple");
            String domain = tags.get("d");
            String selector = tags.get("s");
            String headerList = tags.get("h");
            String bodyHashB64 = tags.get("bh");
            String sigB64 = tags.get("b");

            if (domain == null || selector == null || headerList == null || bodyHashB64 == null || sigB64 == null) {
                return DkimResult.of("MALFORMED", selector, domain, "DKIM-Signature missing required tags (d/s/h/bh/b)");
            }
            if (!"rsa-sha256".equalsIgnoreCase(algo)) {
                return DkimResult.of("UNSUPPORTED", selector, domain, "Algorithm '" + algo + "' not supported by this verifier (only rsa-sha256)");
            }
            String[] canonParts = canon.split("/");
            String headerCanon = canonParts[0];
            String bodyCanon = canonParts.length > 1 ? canonParts[1] : "simple";
            if (!"relaxed".equalsIgnoreCase(headerCanon) || !"relaxed".equalsIgnoreCase(bodyCanon)) {
                return DkimResult.of("UNSUPPORTED", selector, domain,
                        "Canonicalization '" + canon + "' not supported by this verifier (only relaxed/relaxed)");
            }

            // 1. Verify body hash
            String computedBodyHash = base64(sha256(canonicalizeBodyRelaxed(bodySection).getBytes(StandardCharsets.UTF_8)));
            if (!computedBodyHash.equals(bodyHashB64.replaceAll("\\s+", ""))) {
                return DkimResult.of("FAIL", selector, domain, "Body hash mismatch — message body was altered after signing");
            }

            // 2. Fetch public key from DNS
            String dnsName = selector + "._domainkey." + domain;
            String pTag = queryDkimPublicKey(dnsName);
            if (pTag == null || pTag.isBlank()) {
                return DkimResult.of("NO_KEY", selector, domain, "No DKIM public key found at DNS record " + dnsName);
            }

            PublicKey publicKey;
            try {
                byte[] keyBytes = Base64.getDecoder().decode(pTag.replaceAll("\\s+", ""));
                X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
                publicKey = KeyFactory.getInstance("RSA").generatePublic(spec);
            } catch (Exception e) {
                return DkimResult.of("MALFORMED", selector, domain, "Could not parse DKIM public key: " + e.getMessage());
            }

            // 3. Build the canonicalized signed-header block (h= list, relaxed) + the
            //    DKIM-Signature header itself with b= stripped, per RFC 6376 §3.7
            Map<String, String> headerMap = extractHeaders(rawHeaderSection);
            StringBuilder signedBlock = new StringBuilder();
            for (String hName : headerList.split(":")) {
                String key = hName.trim().toLowerCase(Locale.ROOT);
                String val = headerMap.get(key);
                if (val != null) {
                    signedBlock.append(key).append(':').append(relaxHeaderValue(val)).append("\r\n");
                }
            }
            // The DKIM-Signature header itself, with b= value emptied
            String sigHeaderForHash = "dkim-signature:" + relaxHeaderValue(
                    dkimSignatureHeaderValue.replaceAll("(?is)(\\bb\\s*=\\s*)[^;]*", "$1"));
            signedBlock.append(sigHeaderForHash);

            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(publicKey);
            sig.update(signedBlock.toString().getBytes(StandardCharsets.UTF_8));
            boolean valid = sig.verify(Base64.getDecoder().decode(sigB64.replaceAll("\\s+", "")));

            return valid
                    ? DkimResult.of("PASS", selector, domain, "Cryptographic signature verified against DNS public key at " + dnsName)
                    : DkimResult.of("FAIL", selector, domain, "Signature does not match — headers were altered after signing or key mismatch");

        } catch (Exception e) {
            log.warn("DKIM verification error: {}", e.toString());
            return DkimResult.of("ERROR", null, null, "Verification failed: " + e.getMessage());
        }
    }

    private String queryDkimPublicKey(String dnsName) {
        try {
            Lookup lookup = new Lookup(dnsName, Type.TXT);
            lookup.setCache(null);
            Record[] records = lookup.run();
            if (records == null) return null;
            for (Record r : records) {
                String val = r.rdataToString().replace("\"", "");
                Matcher m = Pattern.compile("(?i)p=([A-Za-z0-9+/=\\s]+?)(;|$)").matcher(val);
                if (m.find()) return m.group(1);
            }
        } catch (Exception ignored) {}
        return null;
    }

    private Map<String, String> parseTags(String header) {
        Map<String, String> tags = new LinkedHashMap<>();
        String flattened = header.replaceAll("\\r?\\n", "");
        for (String part : flattened.split(";")) {
            int eq = part.indexOf('=');
            if (eq > 0) {
                tags.put(part.substring(0, eq).trim(), part.substring(eq + 1).trim());
            }
        }
        return tags;
    }

    /** Re-extracts raw, unfolded header values (case-insensitive keys) from the header block. */
    private Map<String, String> extractHeaders(String rawHeaderSection) {
        Map<String, String> map = new LinkedHashMap<>();
        if (rawHeaderSection == null) return map;
        String[] lines = rawHeaderSection.split("\n");
        String currentKey = null;
        StringBuilder currentVal = new StringBuilder();
        for (String line : lines) {
            if ((line.startsWith(" ") || line.startsWith("\t")) && currentKey != null) {
                currentVal.append(" ").append(line.trim());
            } else {
                if (currentKey != null) map.put(currentKey, currentVal.toString());
                int colon = line.indexOf(':');
                if (colon > 0) {
                    currentKey = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
                    currentVal = new StringBuilder(line.substring(colon + 1).trim());
                } else {
                    currentKey = null;
                }
            }
        }
        if (currentKey != null) map.put(currentKey, currentVal.toString());
        return map;
    }

    /** RFC 6376 relaxed header canonicalization: collapse WSP, trim ends. */
    private String relaxHeaderValue(String value) {
        return value.trim().replaceAll("[ \\t]+", " ");
    }

    /** RFC 6376 relaxed body canonicalization: collapse WSP per line, strip trailing blank lines. */
    private String canonicalizeBodyRelaxed(String body) {
        if (body == null) body = "";
        String[] lines = body.replace("\r\n", "\n").split("\n", -1);
        List<String> out = new ArrayList<>();
        for (String line : lines) {
            out.add(line.replaceAll("[ \\t]+", " ").replaceAll("[ \\t]+$", ""));
        }
        int end = out.size();
        while (end > 0 && out.get(end - 1).isEmpty()) end--;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < end; i++) sb.append(out.get(i)).append("\r\n");
        return sb.length() == 0 ? "" : sb.toString();
    }

    private byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    private String base64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }
}
