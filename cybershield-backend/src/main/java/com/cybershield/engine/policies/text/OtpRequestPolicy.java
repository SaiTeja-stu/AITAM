package com.cybershield.engine.policies.text;

import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.regex.Pattern;

/**
 * MSG-02: message asks the recipient to share an OTP / PIN / CVV. Always critical.
 * A genuine OTP message *delivers* a code and warns "do not share it", so warnings are removed before matching.
 */
@Component
public class OtpRequestPolicy extends AbstractPolicy {

    private static final String SECRET = "(?:otp|one[- ]?time (?:password|code|pin)|pin|cvv|verification code|security code|6[- ]digit code)";

    /** "do not share this code with anyone", "never disclose your OTP" and similar safety warnings. */
    private static final Pattern WARNING = Pattern.compile(
            "\\b(?:do not|don't|dont|never|not to|please do not|kindly do not|do not ever)\\s+(?:share|disclose|give|reveal|tell|provide|forward|send|reveal)\\b[^.!\\n]{0,60}");

    /** "share your OTP", "send the code", "tell me the pin" - an imperative aimed at the reader. */
    private static final Pattern ASK_VERB_FIRST = Pattern.compile(
            "\\b(?:share|send|tell|provide|forward|give|reveal|read out|reply with|submit)\\b(?:\\W+\\w+){0,6}?\\W+" + SECRET + "\\b");

    /** "OTP received, share it now", "enter your pin and send". */
    private static final Pattern ASK_SECRET_FIRST = Pattern.compile(
            "\\b" + SECRET + "\\b(?:\\W+\\w+){0,6}?\\W+(?:share|send|forward|tell)\\s+(?:it|this|that|me|us)\\b");

    /** "share OTP 5533 with the delivery partner" - handing a delivery code to the person at your door is normal. */
    private static final Pattern DELIVERY_HANDOVER = Pattern.compile(
            "\\b(?:share|give|tell|provide)\\b[^.!\\n]{0,40}?\\b(?:delivery (?:partner|agent|executive|person|boy)|rider|driver|courier partner)\\b[^.!\\n]{0,20}");

    private static final Pattern DIGIT_CODE = Pattern.compile("\\b\\d{4,8}\\b");

    public OtpRequestPolicy() {
        super("MSG-02", TEXT_LIKE);
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        String t = Keywords.lower(ctx.text().isBlank() ? ctx.rawContent() : ctx.text());
        if (t.isBlank()) return List.of();

        String requestOnly = WARNING.matcher(t).replaceAll(" ");
        if (DIGIT_CODE.matcher(requestOnly).find()) requestOnly = DELIVERY_HANDOVER.matcher(requestOnly).replaceAll(" ");
        if (ASK_VERB_FIRST.matcher(requestOnly).find() || ASK_SECRET_FIRST.matcher(requestOnly).find()) {
            return one("Asks you to share a one-time code",
                    "Anyone who asks for your OTP, PIN or CVV is committing fraud. No bank, company or official ever needs it.",
                    Severity.CRITICAL, 50);
        }
        return List.of();
    }
}
