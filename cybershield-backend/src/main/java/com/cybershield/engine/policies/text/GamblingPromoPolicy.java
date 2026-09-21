package com.cybershield.engine.policies.text;

import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * MSG-07: SMS / e-mail / chat that promotes real-money betting or gambling ("join betting, 100% bonus, deposit Rs 500").
 * Unsolicited betting offers are illegal in most states and a common front for payment fraud, so they are never "safe".
 */
@Component
public class GamblingPromoPolicy extends AbstractPolicy {

    private static final Pattern GAMBLING = Pattern.compile(
            "\\b(betting|online bet|bet on|satta|matka|teen ?patti|casino|rummy|poker|jackpot|1xbet|dafabet|parimatch|betway|bet365|mostbet|fun88"
            + "|ipl bet|cricket bet|color prediction|colour prediction|aviator|lucky ?draw game)\\b",
            Pattern.CASE_INSENSITIVE);

    private static final String[] LURE = {
            "deposit", "bonus", "win ", "earn", "withdraw", "free", "guaranteed", "daily", "join", "register",
            "sign up", "signup", "recharge", "whatsapp", "telegram", "cashback", "100%", "refer", "id ", "rs.", "rs ", "inr", "₹"};

    public GamblingPromoPolicy() {
        super("MSG-07", TEXT_LIKE);
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        String t = Keywords.lower(ctx.text().isBlank() ? ctx.rawContent() : ctx.text());
        if (t.isBlank() || !GAMBLING.matcher(t).find()) return List.of();
        int lure = 0;
        for (String w : LURE) if (t.contains(w)) lure++;
        if (lure == 0) return List.of();

        List<Signal> out = new ArrayList<>();
        out.add(signal("Betting / gambling promotion",
                "The message pushes real-money betting or casino games. Unsolicited betting offers are illegal in many states "
                        + "and are a common front for payment fraud.", Severity.HIGH, 35));
        out.add(signal("Payment-fraud risk",
                "Betting schemes take deposits, then refuse withdrawals or ask for more money and card details.",
                Severity.MEDIUM, 15));
        return out;
    }
}
