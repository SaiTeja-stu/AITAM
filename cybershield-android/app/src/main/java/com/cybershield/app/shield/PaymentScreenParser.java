package com.cybershield.app.shield;

import android.view.accessibility.AccessibilityNodeInfo;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pulls the payee VPA and amount out of a UPI-app confirmation screen by
 * walking the accessibility node tree. It reads ONLY these fields - it does not
 * collect the rest of the screen. Patterns are heuristic and cover the common
 * layouts of the major Indian UPI apps; per-app tuning can be pushed from the
 * server later.
 */
public class PaymentScreenParser {

    private static final Pattern VPA = Pattern.compile("[a-zA-Z0-9._-]{2,}@[a-zA-Z]{2,}");
    private static final Pattern AMOUNT = Pattern.compile("(?:₹|rs\\.?|inr)\\s?([0-9][0-9,]*(?:\\.[0-9]{1,2})?)",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern PAY_HINT = Pattern.compile(
            "(pay|paying|sending|send money|proceed to pay|confirm payment|to:|payee|requesting)",
            Pattern.CASE_INSENSITIVE);

    public static class Result {
        public String payeeVpa;
        public String payeeName;
        public Double amount;
        public boolean looksLikePaymentScreen;
        public boolean looksLikeCollectRequest;
    }

    public Result parse(AccessibilityNodeInfo root) {
        Result r = new Result();
        if (root == null) return r;

        Deque<AccessibilityNodeInfo> stack = new ArrayDeque<>();
        stack.push(root);
        int visited = 0;
        String prevText = null;

        while (!stack.isEmpty() && visited < 400) {
            AccessibilityNodeInfo node = stack.pop();
            if (node == null) continue;
            visited++;

            CharSequence tc = node.getText();
            CharSequence dc = node.getContentDescription();
            String text = tc != null ? tc.toString() : (dc != null ? dc.toString() : null);

            if (text != null && !text.isEmpty()) {
                String lower = text.toLowerCase(Locale.ROOT);

                if (PAY_HINT.matcher(lower).find()) r.looksLikePaymentScreen = true;
                if (lower.contains("requesting") || lower.contains("collect request")
                        || lower.contains("wants money") || lower.contains("is requesting")) {
                    r.looksLikeCollectRequest = true;
                }

                Matcher vm = VPA.matcher(text);
                if (vm.find() && r.payeeVpa == null) {
                    r.payeeVpa = vm.group();
                    if (prevText != null && prevText.length() < 40 && !VPA.matcher(prevText).find()) {
                        r.payeeName = prevText.trim();
                    }
                }

                Matcher am = AMOUNT.matcher(text);
                if (am.find() && r.amount == null) {
                    try {
                        r.amount = Double.parseDouble(am.group(1).replace(",", ""));
                    } catch (NumberFormatException ignored) { }
                }
                prevText = text;
            }

            for (int i = 0; i < node.getChildCount(); i++) {
                AccessibilityNodeInfo child = node.getChild(i);
                if (child != null) stack.push(child);
            }
        }

        if (r.payeeVpa != null && r.amount != null) r.looksLikePaymentScreen = true;
        return r;
    }
}
