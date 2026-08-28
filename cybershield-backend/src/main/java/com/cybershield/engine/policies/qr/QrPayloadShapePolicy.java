package com.cybershield.engine.policies.qr;

import com.cybershield.domain.ContentType;
import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;
import com.cybershield.qr.PayloadKind;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * QR-03/09: flags the shape of a decoded QR payload.
 *  - a "payment" QR that is actually a plain URL  -> likely fake payment page (HIGH; URL policies also run)
 *  - WiFi / contact / SMS-intent deep links       -> MEDIUM (can silently reconfigure the device)
 *  - unreadable QR                                 -> informational
 */
@Component
public class QrPayloadShapePolicy extends AbstractPolicy {

    public QrPayloadShapePolicy() {
        super("QR-03", Set.of(ContentType.QR));
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        var kindOpt = ctx.qrKind();
        if (kindOpt.isEmpty()) return List.of();
        List<Signal> out = new ArrayList<>();
        PayloadKind kind = kindOpt.get();

        switch (kind) {
            case URL -> out.add(signal("QR opens a web link",
                    "This QR does not start a normal UPI payment - it opens a website. Fake 'payment' pages use this to steal card or UPI details.",
                    Severity.MEDIUM, 12));
            case WIFI -> out.add(signal("QR configures Wi-Fi",
                    "Scanning this could connect your device to an attacker-controlled network.",
                    Severity.MEDIUM, 14));
            case CONTACT -> out.add(signal("QR adds a contact",
                    "This QR wants to save a contact card - harmless by itself but often paired with follow-up scam calls.",
                    Severity.LOW, 5));
            case SMS_INTENT -> out.add(signal("QR pre-composes a text message",
                    "This QR tries to make your phone send an SMS to a number it chose - can trigger premium-rate charges.",
                    Severity.MEDIUM, 16));
            case OTHER -> out.add(signal("QR triggers an app deep-link",
                    "The payload is an app-specific link rather than a payment or website. Treat unexpected deep-links with caution.",
                    Severity.LOW, 6));
            default -> { /* UPI_PAYMENT / PLAIN_TEXT handled elsewhere */ }
        }
        return out;
    }
}
