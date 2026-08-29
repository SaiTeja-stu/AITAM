package com.cybershield.qr;


import java.util.Locale;

/** Classifies a decoded QR string into a {@link PayloadKind} (spec step 3). */
public class PayloadClassifier {

    public PayloadKind classify(String payload) {
        if (payload == null) return PayloadKind.OTHER;
        String s = payload.trim();
        String lower = s.toLowerCase(Locale.ROOT);

        if (lower.startsWith("upi://")) return PayloadKind.UPI_PAYMENT;
        if (lower.startsWith("http://") || lower.startsWith("https://")) return PayloadKind.URL;
        if (lower.startsWith("wifi:")) return PayloadKind.WIFI;
        if (lower.startsWith("begin:vcard") || lower.startsWith("mecard:")) return PayloadKind.CONTACT;
        if (lower.startsWith("smsto:") || lower.startsWith("sms:")) return PayloadKind.SMS_INTENT;
        if (lower.startsWith("tel:")) return PayloadKind.TEL;
        if (lower.startsWith("mailto:")) return PayloadKind.EMAIL;
        if (lower.startsWith("geo:")) return PayloadKind.GEO;

        // Bare domain that looks like a URL without scheme
        if (s.matches("(?i)^[a-z0-9.-]+\\.[a-z]{2,}(/.*)?$")) return PayloadKind.URL;

        // Any other custom scheme (deep link into an app)
        if (s.matches("(?i)^[a-z][a-z0-9+.-]*://.*")) return PayloadKind.OTHER;

        return PayloadKind.PLAIN_TEXT;
    }
}
