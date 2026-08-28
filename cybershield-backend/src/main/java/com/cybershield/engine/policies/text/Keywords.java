package com.cybershield.engine.policies.text;

import java.util.List;
import java.util.Locale;

/** Shared keyword/phrase lists and matching helpers for text-based policies. */
final class Keywords {
    private Keywords() {}

    static final List<String> URGENCY = List.of(
            "act now", "immediately", "within 24 hours", "within 24hrs", "account will be",
            "will be suspended", "will be blocked", "will be closed", "last warning",
            "final notice", "urgent", "expire today", "expires today", "action required",
            "verify now", "click now", "limited time", "failure to comply");

    static final List<String> CREDENTIALS = List.of(
            "password", "login details", "user id and password", "net banking password",
            "card number", "cvv", "card pin", "atm pin", "expiry date", "update your kyc",
            "complete your kyc", "re-kyc", "ekyc", "verify your account", "confirm your identity");

    static final List<String> OTP = List.of(
            "otp", "one time password", "one-time password", "share the code", "share otp",
            "do not share otp", "6 digit code", "verification code", "share the pin");

    static final List<String> UPI_RECEIVE = List.of(
            "scan to receive", "scan this qr to receive", "scan and receive", "accept the request to receive",
            "approve to receive money", "scan to get your refund", "scan for cashback",
            "collect request", "approve request to get");

    static final List<String> PRIZE_JOB = List.of(
            "you have won", "congratulations you", "lottery", "lucky draw", "prize money",
            "claim your reward", "work from home", "earn daily", "part time job", "registration fee",
            "processing fee", "refundable deposit", "task based", "telegram job", "rating job");

    static final List<String> IMPERSONATION_ENTITIES = List.of(
            "income tax department", "cbi", "narcotics", "customs department", "trai",
            "electricity board", "your bank", "kyc team", "rbi", "courier", "fedex", "bluedart",
            "amazon", "flipkart", "police", "cyber cell", "aadhaar");

    static final List<String> CRYPTO = List.of(
            "bitcoin", "btc", "usdt", "ethereum", "crypto wallet", "double your money",
            "guaranteed returns", "investment plan", "trading signals", "binance");

    static final List<String> DIGITAL_ARREST = List.of(
            "digital arrest", "arrest warrant", "your aadhaar has been used", "money laundering case",
            "parcel contains", "illegal items", "do not disconnect", "skype interrogation",
            "verification of your bank account by rbi", "your number will be blocked by trai");

    static boolean containsAny(String textLower, List<String> phrases) {
        for (String p : phrases) {
            if (textLower.contains(p)) return true;
        }
        return false;
    }

    static long countMatches(String textLower, List<String> phrases) {
        return phrases.stream().filter(textLower::contains).count();
    }

    static String lower(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT);
    }
}
