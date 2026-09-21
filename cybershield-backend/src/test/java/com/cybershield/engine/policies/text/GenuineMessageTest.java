package com.cybershield.engine.policies.text;

import com.cybershield.domain.ContentType;
import com.cybershield.engine.PolicyContext;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Genuine OTP / bank messages must stay quiet; real OTP theft and betting promotions must be caught. */
class GenuineMessageTest {

    private final OtpRequestPolicy otp = new OtpRequestPolicy();
    private final GamblingPromoPolicy gambling = new GamblingPromoPolicy();

    private static PolicyContext sms(String text) {
        return PolicyContext.builder(ContentType.SMS).rawContent(text).text(text).build();
    }

    @Test
    void genuine_otp_delivery_with_do_not_share_warning_is_not_flagged() {
        assertThat(otp.evaluate(sms("882787 is your Paytm login OTP. Valid for 5 minutes. Please do not share this code with anyone."))).isEmpty();
        assertThat(otp.evaluate(sms("Your Amazon OTP is 4421. Do not share it with anyone. Amazon will never call you for your OTP."))).isEmpty();
    }

    @Test
    void handing_a_delivery_code_to_the_delivery_partner_is_not_flagged() {
        assertThat(otp.evaluate(sms("Your Swiggy order is out for delivery. Share OTP 5533 with the delivery partner."))).isEmpty();
    }

    @Test
    void asking_the_reader_for_an_otp_is_still_critical() {
        assertThat(otp.evaluate(sms("Dear user please share your OTP with our executive to complete KYC"))).hasSize(1);
        assertThat(otp.evaluate(sms("Tell me the OTP you just received"))).hasSize(1);
        assertThat(otp.evaluate(sms("URGENT: your SBI account is blocked. Verify KYC and share the OTP now"))).hasSize(1);
    }

    @Test
    void betting_promotion_without_a_link_is_flagged() {
        assertThat(gambling.evaluate(sms("Hi, I am from IPL online betting. Deposit Rs 500 and get Rs 5000 free."))).hasSize(2);
        assertThat(gambling.evaluate(sms("Play teen patti online and win real cash. Deposit Rs 200 get 100% bonus."))).hasSize(2);
    }

    @Test
    void ordinary_messages_are_not_gambling() {
        assertThat(gambling.evaluate(sms("Rs 2,500 debited from A/c XX1234 to VPA abc@ybl. Not you? Call the bank."))).isEmpty();
        assertThat(gambling.evaluate(sms("I placed a better offer on the flat, deposit paid yesterday."))).isEmpty();
    }
}
