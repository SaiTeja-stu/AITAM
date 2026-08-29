package com.cybershield.engine.policies.qr;

import com.cybershield.common.Hashing;
import com.cybershield.domain.ContentType;
import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;
import com.cybershield.intel.LocalIntelStore;
import com.cybershield.qr.UpiUri;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * QR-02/06/08: analyses the recipient of a UPI payment QR.
 *  - payee VPA on the community fraud list           -> CRITICAL
 *  - display name vs VPA handle mismatch             -> HIGH
 *  - individual-looking VPA presented as a merchant  -> MEDIUM
 *  - large pre-filled amount + suspicious note        -> HIGH
 */
@Component
public class UpiPaymentPolicy extends AbstractPolicy {

    private static final Set<String> MERCHANT_HANDLES = Set.of(
            "ybl", "okhdfcbank", "okaxis", "okicici", "oksbi", "paytm", "apl", "yapl", "abfspay");

    private final LocalIntelStore intel;
    private final Hashing hashing;

    public UpiPaymentPolicy(LocalIntelStore intel, Hashing hashing) {
        super("QR-02", Set.of(ContentType.QR));
        this.intel = intel;
        this.hashing = hashing;
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        var opt = ctx.upi();
        if (opt.isEmpty() || !opt.get().valid()) return List.of();
        UpiUri upi = opt.get();
        List<Signal> out = new ArrayList<>();

        String vpa = upi.payeeVpa().orElse("");
        if (!vpa.isBlank() && intel.isReportedVpaHash(hashing.hmac(vpa))) {
            out.add(signal("Recipient reported for fraud",
                    "This UPI ID has been reported by other users as fraudulent.",
                    Severity.CRITICAL, 55));
        }

        String pn = upi.payeeName().orElse("").trim();
        String handle = vpa.contains("@") ? vpa.substring(vpa.indexOf('@') + 1).toLowerCase(Locale.ROOT) : "";
        String vpaUser = vpa.contains("@") ? vpa.substring(0, vpa.indexOf('@')) : vpa;

        // registered merchant QRs use an opaque handle (paytmqr…, bharatpe…, a
        // merchant code) that never matches the shop name — that's expected, not a mismatch.
        boolean registeredMerchant = upi.merchantCode().isPresent()
                || vpaUser.toLowerCase(Locale.ROOT).matches("^(paytmqr|bharatpe|merchant|mab|q\\d).*")
                || MERCHANT_HANDLES.contains(handle) && vpaUser.length() > 10;

        if (!registeredMerchant && !pn.isBlank() && !vpaUser.isBlank()
                && !normalized(vpaUser).contains(normalized(firstToken(pn)))
                && !normalized(pn).contains(normalized(vpaUser))) {
            out.add(signal("Name does not match the UPI ID",
                    "The QR shows the payee as '" + pn + "' but the UPI ID belongs to '" + vpaUser + "'.",
                    Severity.HIGH, 22));
        }

        boolean looksIndividual = !handle.isBlank() && !MERCHANT_HANDLES.contains(handle)
                && upi.merchantCode().isEmpty();
        boolean framedAsMerchant = pn.toLowerCase(Locale.ROOT).matches(".*(store|shop|mart|enterprise|traders|pay|technologies|pvt|ltd).*");
        if (looksIndividual && framedAsMerchant) {
            out.add(signal("Personal account posing as a business",
                    "The name looks like a business but the UPI ID is a personal account with no merchant registration.",
                    Severity.MEDIUM, 15));
        }

        double amount = upi.amount().orElse(0.0);
        String note = upi.note().orElse("").toLowerCase(Locale.ROOT);
        boolean badNote = note.contains("refund") || note.contains("verify") || note.contains("prize")
                || note.contains("cashback") || note.contains("penalty") || note.contains("kyc");
        if (amount >= 2000 && badNote) {
            out.add(signal("Large pre-filled amount with a suspicious reason",
                    "The QR fixes a payment of " + fmt(amount) + " described as '" + note + "'.",
                    Severity.HIGH, 24));
        } else if (amount >= 2000) {
            out.add(signal("Amount is pre-filled",
                    "This QR fixes the amount at " + fmt(amount) + " - verify it is correct before paying.",
                    Severity.LOW, 5));
        }
        return out;
    }

    private String fmt(double a) {
        return "Rs " + (a == Math.floor(a) ? String.valueOf((long) a) : String.valueOf(a));
    }
    private String firstToken(String s) {
        String[] p = s.trim().split("\\s+");
        return p.length > 0 ? p[0] : s;
    }
    private String normalized(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
    }
}
