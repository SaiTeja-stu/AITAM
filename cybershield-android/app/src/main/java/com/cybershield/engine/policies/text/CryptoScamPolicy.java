package com.cybershield.engine.policies.text;

import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;

import java.util.List;
import java.util.regex.Pattern;

/** MSG-08: crypto "guaranteed returns" / wallet-address scam. */
public class CryptoScamPolicy extends AbstractPolicy {

    private static final Pattern BTC = Pattern.compile("\\b(bc1[a-z0-9]{20,}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\\b");
    private static final Pattern ETH = Pattern.compile("\\b0x[a-fA-F0-9]{40}\\b");

    public CryptoScamPolicy() {
        super("MSG-08", TEXT_LIKE);
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        String raw = ctx.text().trim().isEmpty() ? ctx.rawContent() : ctx.text();
        String t = Keywords.lower(raw);
        if (t.trim().isEmpty()) return List.of();

        boolean walletAddr = BTC.matcher(raw).find() || ETH.matcher(raw).find();
        boolean hype = Keywords.countMatches(t, Keywords.CRYPTO) >= 1
                && (t.contains("double") || t.contains("guaranteed") || t.contains("profit")
                    || t.contains("returns") || t.contains("invest"));
        if (walletAddr && (hype || Keywords.countMatches(t, Keywords.CRYPTO) >= 1)) {
            return one("Crypto payment / investment scam",
                    "The message contains a crypto wallet address alongside profit promises. Transfers to it cannot be reversed.",
                    Severity.HIGH, 26);
        }
        if (hype) {
            return one("Unrealistic investment promise",
                    "Claims of guaranteed or doubled returns are a hallmark of investment fraud.",
                    Severity.MEDIUM, 16);
        }
        return List.of();
    }
}
