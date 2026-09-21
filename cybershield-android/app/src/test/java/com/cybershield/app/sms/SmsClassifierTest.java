package com.cybershield.app.sms;

import org.junit.Test;
import static org.junit.Assert.*;

public class SmsClassifierTest {

    @Test
    public void testDltHeaderParsing() {
        SmsClassifier.DltHeaderInfo info = SmsClassifier.parseDltHeader("VK-HDFCBK-T");
        assertTrue(info.isDltShaped);
        assertEquals("VK", info.prefix);
        assertEquals("hdfcbk", info.entity);
        assertEquals("t", info.typeSuffix);
        assertTrue(info.isKnownEntity);

        SmsClassifier.DltHeaderInfo info2 = SmsClassifier.parseDltHeader("JD-SBIINB-S");
        assertTrue(info2.isDltShaped);
        assertEquals("JD", info2.prefix);
        assertEquals("sbiinb", info2.entity);
        assertEquals("s", info2.typeSuffix);

        SmsClassifier.DltHeaderInfo info3 = SmsClassifier.parseDltHeader("AX-AIRTEL-P");
        assertTrue(info3.isDltShaped);
        assertEquals("p", info3.typeSuffix);

        SmsClassifier.DltHeaderInfo info4 = SmsClassifier.parseDltHeader("+919812345678");
        assertFalse(info4.isDltShaped);
    }

    @Test
    public void testLegitimateBankTransactionNotFlaggedAsFraud() {
        // Authentic bank message with debit info and urgent fraud helpline advisory
        String text = "Rs. 5,000 debited from A/C XX1234 on 08-09-26. UPI ref 928371. Avl Bal: Rs 42,000. "
                + "If not done by you, immediately call 18002026161 or SMS BLOCK to 5676712.";

        // Even if local engine scored risk due to "immediately" / "BLOCK" / "call"
        SmsClassifier.Category cat = SmsClassifier.classify("VK-HDFCBK-T", text, true, false);
        assertEquals(SmsClassifier.Category.TRANSACTIONAL, cat);
        assertFalse("Genuine bank alert should not trigger fraud warning", SmsClassifier.isAlertWorthy(cat));

        // Classic 2-char DLT header without -T suffix
        SmsClassifier.Category cat2 = SmsClassifier.classify("VM-HDFCBK", text, true, false);
        assertEquals(SmsClassifier.Category.TRANSACTIONAL, cat2);
        assertFalse(SmsClassifier.isAlertWorthy(cat2));
    }

    @Test
    public void testLegitimateOtpNotFlaggedAsFraud() {
        String text = "492018 is your OTP for HDFC NetBanking login. Valid for 5 mins. Do not share with anyone.";
        SmsClassifier.Category cat = SmsClassifier.classify("VK-HDFCBK-T", text, false, false);
        assertEquals(SmsClassifier.Category.OTP, cat);
        assertFalse(SmsClassifier.isAlertWorthy(cat));
    }

    @Test
    public void testGovernmentCommunication() {
        String text = "Dear Citizen, Link your Aadhaar with Voter ID. Visit https://voters.eci.gov.in";
        SmsClassifier.Category cat = SmsClassifier.classify("GO-MYGOV-G", text, false, false);
        assertEquals(SmsClassifier.Category.GOVERNMENT, cat);
        assertFalse(SmsClassifier.isAlertWorthy(cat));
    }

    @Test
    public void testFakeBankSmsFromPersonalNumberFlaggedAsFraud() {
        // Message pretending to be SBI but sent from a +91 10-digit mobile number
        String text = "Dear customer, your SBI account KYC is pending. Update your PAN card and verify "
                + "at http://sbi-kyc-verify.tk now or your account will be blocked.";
        SmsClassifier.Category cat = SmsClassifier.classify("+919812345678", text, true, false);
        assertEquals(SmsClassifier.Category.FRAUD, cat);
        assertTrue(SmsClassifier.isAlertWorthy(cat));
    }

    @Test
    public void testLookAlikeSpoofedDltHeaderFlaggedAsFraud() {
        // Spoofed lookalike header HDFCBNK (edit distance 1 from HDFCBK)
        String text = "Your HDFC account has been credited with Rs 50,000. Verify at http://fake.com";
        SmsClassifier.Category cat = SmsClassifier.classify("VK-HDFCBNK-T", text, false, false);
        assertEquals(SmsClassifier.Category.FRAUD, cat);
        assertTrue(SmsClassifier.isAlertWorthy(cat));
    }

    @Test
    public void testHardOtpTheftFlaggedAsFraud() {
        // Message asking user to share their OTP
        String text = "Our executive is on call. Please share the OTP 482910 to confirm your refund.";
        SmsClassifier.Category cat = SmsClassifier.classify("VK-HDFCBK-T", text, false, false);
        assertEquals(SmsClassifier.Category.FRAUD, cat);
        assertTrue(SmsClassifier.isAlertWorthy(cat));
    }
}
