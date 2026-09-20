package com.cybershield.forensics;

import java.util.List;
import java.util.Map;

/**
 * Pre-bundled realistic RFC-5322 email samples for live SIH demonstration.
 */
public final class SampleEmails {

    private SampleEmails() {}

    public static final String RUSSIAN_PHISHING_EML =
            "Received: from mx1.target-inbox.in (14.139.58.20) by mail.target.gov.in with ESMTP id ABC12345 for <director@institution.edu.in>; Tue, 15 Sep 2026 14:32:10 +0530\n" +
            "Received: from tor-relay.frankfurt.de (185.220.101.5) by mx1.target-inbox.in with ESMTP id HOP2; Tue, 15 Sep 2026 09:01:45 +0000\n" +
            "Received: from mail.bulletproof-spb.ru (91.240.118.42) by tor-relay.frankfurt.de with ESMTP id HOP1; Tue, 15 Sep 2026 08:59:12 +0000\n" +
            "Authentication-Results: mx1.target-inbox.in; spf=fail (sender IP 91.240.118.42 not permitted) smtp.mailfrom=sec-alert@micros0ft-support.ru; dkim=fail header.d=micros0ft-support.ru; dmarc=fail\n" +
            "From: \"Microsoft 365 Security Team\" <sec-alert@micros0ft-support.ru>\n" +
            "To: director@institution.edu.in\n" +
            "Reply-To: attacker-inbox@yopmail.com\n" +
            "Return-Path: <bounces@micros0ft-support.ru>\n" +
            "Subject: [URGENT ACTION REQUIRED] Immediate Password Expiry & Account Suspension\n" +
            "Date: Tue, 15 Sep 2026 11:58:00 +0300\n" +
            "Message-ID: <20260915115800.91240118.phish@micros0ft-support.ru>\n" +
            "MIME-Version: 1.0\n" +
            "Content-Type: text/html; charset=UTF-8\n" +
            "\n" +
            "<html><body>\n" +
            "<p>Dear Account Holder,</p>\n" +
            "<p>Your Microsoft 365 enterprise institutional access will be terminated within 2 hours due to unverified compliance certificates.</p>\n" +
            "<p>To retain uninterrupted mailbox privileges, click below immediately to verify your credentials:</p>\n" +
            "<p><a href=\"https://micros0ft-verify-portal.ru/auth/login?user=director\">Verify Account Credentials Now</a></p>\n" +
            "<p>Failure to act will result in catastrophic data forfeiture.</p>\n" +
            "<p>Regards,<br/>Office 365 Global Incident Team</p>\n" +
            "</body></html>";

    public static final String NIGERIAN_BEC_WIRE_FRAUD =
            "Received: from mx.corporate-gateway.co.in (49.36.12.105) by exchange.company.in with ESMTP id XYZ8899; Tue, 15 Sep 2026 16:15:20 +0530\n" +
            "Received: from albacore-proxy.amsterdam.nl (45.142.122.18) by mx.corporate-gateway.co.in with ESMTP id AMST99; Tue, 15 Sep 2026 10:44:02 +0000\n" +
            "Received: from mtn-client.lagos.ng (105.112.44.89) by albacore-proxy.amsterdam.nl with ESMTP id LAGOS01; Tue, 15 Sep 2026 11:42:15 +0100\n" +
            "Authentication-Results: mx.corporate-gateway.co.in; spf=softfail (IP 105.112.44.89) smtp.mailfrom=ceo-office@gmail.com; dkim=none; dmarc=fail\n" +
            "From: \"Prof. T. G. Sitharam (Chairman AICTE)\" <executive.chairman.office12@gmail.com>\n" +
            "To: accounts-finance@institution.edu.in\n" +
            "Reply-To: confidential-executive99@proton.me\n" +
            "Return-Path: <executive.chairman.office12@gmail.com>\n" +
            "Subject: Highly Confidential - Urgent Emergency Vendor Settlement Authorization\n" +
            "Date: Tue, 15 Sep 2026 11:41:00 +0100\n" +
            "Message-ID: <CA+G3BEC202609151141@mail.gmail.com>\n" +
            "MIME-Version: 1.0\n" +
            "Content-Type: text/plain; charset=UTF-8\n" +
            "\n" +
            "Dear Finance Officer,\n\n" +
            "I am currently chairing an emergency closed-door committee session with the Ministry and cannot take direct voice calls.\n\n" +
            "We have an immediate statutory obligation requiring urgent wire transfer remittance of ₹ 14,80,000 to our empanelled technical auditor before 4:00 PM today to avert project audit embargo.\n\n" +
            "Beneficiary Bank: Apex Offshore Commercial Bank\n" +
            "Account Number: 998822019283\n" +
            "IFSC / SWIFT: APEXINBB019\n\n" +
            "Treat this with utmost confidentiality. Process the RTGS immediately and send the transaction acknowledgment slip directly to my private email.\n\n" +
            "Prof. T. G. Sitharam\n" +
            "Chairman, AICTE";

    public static final String SPOOFED_SBI_BANK_EML =
            "Received: from mx.vsnl.net.in (122.160.88.14) by mail.user.in with ESMTP id IN0021; Tue, 15 Sep 2026 12:10:05 +0530\n" +
            "Received: from vps-ovh.paris.fr (89.248.165.70) by mx.vsnl.net.in with ESMTP id RELAY44; Tue, 15 Sep 2026 06:39:10 +0000\n" +
            "Authentication-Results: mx.vsnl.net.in; spf=fail (domain sbi.co.in does not permit 89.248.165.70); dkim=fail; dmarc=fail\n" +
            "From: \"State Bank of India Online Banking\" <customer-support@sbi-kyc-update-portal.info>\n" +
            "To: customer@mail.in\n" +
            "Reply-To: support@sbi-kyc-update-portal.info\n" +
            "Subject: Important Alert: Your SBI YONO Net Banking Access is Blocked Due to Expired PAN KYC\n" +
            "Date: Tue, 15 Sep 2026 08:35:00 +0200\n" +
            "Message-ID: <SBI20260915-KYC9918@sbi-kyc-update-portal.info>\n" +
            "Content-Type: text/html; charset=UTF-8\n" +
            "\n" +
            "<html><body>\n" +
            "<p>Dear SBI Customer,</p>\n" +
            "<p>In accordance with RBI mandate circular RBI/2026/78, your savings account privileges have been put on hold due to pending PAN Aadhaar linkage.</p>\n" +
            "<p>Update your credentials within 24 hours to avoid a permanent penalty fine of ₹ 5,000:</p>\n" +
            "<p><a href=\"http://sbi-kyc-update-portal.info/login.php\">Update SBI YONO KYC Online</a></p>\n" +
            "<p>SBI Customer Care: 1800-425-3800</p>\n" +
            "</body></html>";

    public static final String CLEAN_AICTE_NOTIFICATION =
            "Received: from mx.institution.edu.in (14.139.58.20) by mail.dept.edu.in with ESMTP id OK9001; Tue, 15 Sep 2026 10:00:15 +0530\n" +
            "Received: from mail-relay.aicte-india.org (14.139.1.50) by mx.institution.edu.in with ESMTPS id NKN001; Tue, 15 Sep 2026 09:59:45 +0530\n" +
            "Authentication-Results: mx.institution.edu.in; spf=pass (sender IP 14.139.1.50 matches v=spf1) smtp.mailfrom=notifications@aicte-india.org; dkim=pass header.d=aicte-india.org; dmarc=pass\n" +
            "From: \"AICTE Cybersecurity Cell\" <notifications@aicte-india.org>\n" +
            "To: hod-cse@institution.edu.in\n" +
            "Reply-To: notifications@aicte-india.org\n" +
            "Return-Path: <bounces@aicte-india.org>\n" +
            "Subject: Circular: Smart India Hackathon (SIH) 2026 Evaluation Schedule & Platform Guidelines\n" +
            "Date: Tue, 15 Sep 2026 09:58:30 +0530\n" +
            "Message-ID: <AICTE-2026-SIH-99281@aicte-india.org>\n" +
            "Content-Type: text/plain; charset=UTF-8\n" +
            "\n" +
            "Respected Head of Department,\n\n" +
            "This is an official circular regarding the Smart India Hackathon (SIH) 2026 grand finale schedule and evaluation criteria for Problem Statement SIH26106.\n\n" +
            "Institutions are advised to review the cybersecurity forensic platform requirements at the official AICTE portal: https://aicte-india.org/sih2026.\n\n" +
            "Warm regards,\nCyber Security Cell\nAll India Council for Technical Education (AICTE)\nNelson Mandela Marg, Vasant Kunj, New Delhi-110070";

    public static List<Map<String, String>> sampleCatalog() {
        return List.of(
                Map.of(
                        "id", "RUSSIAN_PHISHING",
                        "title", "1. Targeted Microsoft 365 Phishing (Origin: Russia / Tor Relay)",
                        "threatLevel", "MALICIOUS",
                        "description", "State-sponsored lookalike domain, origin IP in St. Petersburg routed through Frankfurt Tor exit relay, SPF/DMARC failed.",
                        "content", RUSSIAN_PHISHING_EML
                ),
                Map.of(
                        "id", "NIGERIAN_BEC",
                        "title", "2. High-Severity BEC Wire Fraud (Origin: Lagos, Nigeria)",
                        "threatLevel", "CRITICAL_BEC",
                        "description", "Executive Impersonation of AICTE Chairman demanding urgent ₹14.8L wire transfer with reply-to diversion.",
                        "content", NIGERIAN_BEC_WIRE_FRAUD
                ),
                Map.of(
                        "id", "SBI_SPOOF",
                        "title", "3. Banking Phishing & PAN-KYC Deactivation (Origin: Paris VPS)",
                        "threatLevel", "MALICIOUS",
                        "description", "Spoofed SBI YONO banking notification with lookalike phishing domain and urgent fine threats.",
                        "content", SPOOFED_SBI_BANK_EML
                ),
                Map.of(
                        "id", "CLEAN_AICTE",
                        "title", "4. Clean Institutional Circular (Origin: AICTE New Delhi / NKN)",
                        "threatLevel", "LEGITIMATE",
                        "description", "Authentic academic circular from AICTE New Delhi through National Knowledge Network with valid SPF, DKIM, and DMARC.",
                        "content", CLEAN_AICTE_NOTIFICATION
                )
        );
    }
}
