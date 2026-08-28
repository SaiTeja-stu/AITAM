package com.cybershield.analyze;

import com.cybershield.domain.ContentType;
import com.cybershield.domain.RiskLevel;
import com.cybershield.domain.Signal;
import com.cybershield.domain.Verdict;
import com.cybershield.qr.UpiUri;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Builds the plain-language explanation and safe-browsing recommendations
 * (problem statement: "Explanation of why content is risky", "Safe browsing
 * recommendations"). Deterministic and offline. An LLM can be layered on top
 * later for nicer prose - the signal list is the contract either way.
 *
 * Wording rules are enforced here: no "100% safe/authorised"; degrade to
 * "no suspicious indicators detected" when nothing negative fired.
 */
@Service
public class ExplanationService {

    public void enrich(Verdict v, ContentType type, UpiUri upi, boolean initiatesPayment) {
        v.setExplanation(buildExplanation(v, type, initiatesPayment));
        addRecommendations(v, type, upi, initiatesPayment);
        addCategories(v);
    }

    private String buildExplanation(Verdict v, ContentType type, boolean initiatesPayment) {
        List<Signal> negative = v.getSignals().stream().filter(s -> s.weight() > 0).toList();
        StringBuilder sb = new StringBuilder();

        if (v.isVerified()) {
            sb.append("This has been positively confirmed by an authoritative source. ");
        } else if (negative.isEmpty()) {
            sb.append("We checked this ").append(nice(type))
              .append(" and found no suspicious indicators. This is not a guarantee of safety - "
                    + "always verify the sender or recipient independently. ");
        } else {
            sb.append("This ").append(nice(type)).append(" shows ")
              .append(negative.size() == 1 ? "a warning sign" : negative.size() + " warning signs")
              .append(": ");
            sb.append(String.join("; ", negative.stream()
                    .limit(4)
                    .map(s -> s.name().toLowerCase() + " (" + s.detail() + ")")
                    .toList()));
            sb.append(". ");
        }

        if (initiatesPayment) {
            sb.append("Scanning a QR or approving a UPI request never credits your account - it only sends money out. "
                    + "If anyone told you to scan this to RECEIVE money, a refund, or a reward, it is a scam. ");
        }

        RiskLevel lvl = v.getRiskLevel();
        if (lvl == RiskLevel.MALICIOUS) {
            sb.append("Do not interact with it and report it.");
        } else if (lvl == RiskLevel.HIGH_RISK) {
            sb.append("Treat it as unsafe and do not act on it.");
        } else if (lvl == RiskLevel.SUSPICIOUS) {
            sb.append("Be cautious and confirm through a channel you already trust.");
        }
        return sb.toString().trim();
    }

    private void addRecommendations(Verdict v, ContentType type, UpiUri upi, boolean initiatesPayment) {
        RiskLevel lvl = v.getRiskLevel();

        if (initiatesPayment) {
            v.addRecommendation("Do not pay if someone asked you to scan this to receive money or a refund.");
            if (upi != null && upi.isCollectOrMandate()) {
                v.addRecommendation("This is a request to pull money FROM you - decline unless you started it.");
            }
            v.addRecommendation("Confirm the recipient's real UPI ID through an official app or website.");
        }

        if (lvl == RiskLevel.MALICIOUS || lvl == RiskLevel.HIGH_RISK) {
            v.addRecommendation("Do not click any links, download attachments, or enter any details.");
            v.addRecommendation("Report this content so others are protected.");
            if (type == ContentType.EMAIL || type == ContentType.SMS || type == ContentType.SOCIAL) {
                v.addRecommendation("Block the sender and delete the message.");
            }
        } else if (lvl == RiskLevel.SUSPICIOUS) {
            v.addRecommendation("Verify independently: type the official address yourself instead of following links.");
            v.addRecommendation("Never share OTP, passwords, card numbers or KYC details in response to a message.");
        } else {
            v.addRecommendation("Stay alert: legitimate-looking content can still be a scam. Verify unexpected requests.");
        }
        v.addRecommendation("When in doubt, contact the organisation using a number from their official website.");
    }

    private void addCategories(Verdict v) {
        for (Signal s : v.getSignals()) {
            String id = s.policyId();
            if (id.startsWith("URL")) v.addCategory("suspicious-link");
            if (id.equals("URL-01") || id.equals("URL-05")) v.addCategory("brand-impersonation");
            if (id.startsWith("WEB")) v.addCategory("phishing-page");
            if (id.equals("MSG-02")) v.addCategory("credential-theft");
            if (id.equals("MSG-03") || id.startsWith("QR")) v.addCategory("payment-fraud");
            if (id.equals("MSG-05")) v.addCategory("advance-fee-scam");
            if (id.equals("MSG-08")) v.addCategory("investment-scam");
            if (id.equals("MSG-10")) v.addCategory("extortion");
            if (id.startsWith("X-")) v.addCategory("known-campaign");
        }
    }

    private String nice(ContentType t) {
        return switch (t) {
            case URL -> "link";
            case WEBPAGE -> "web page";
            case EMAIL -> "email";
            case SMS -> "text message";
            case SOCIAL -> "social-media message";
            case QR -> "QR code";
        };
    }
}
