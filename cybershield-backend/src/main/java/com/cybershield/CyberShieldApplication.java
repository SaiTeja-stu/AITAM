package com.cybershield;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

// We authenticate via our own JWT filter, not the default form-login user,
// so disable the auto-configured in-memory user (and its "generated password" log line).
@SpringBootApplication(exclude = UserDetailsServiceAutoConfiguration.class)
@EnableScheduling
@EnableAsync
public class CyberShieldApplication {
    public static void main(String[] args) {
        SpringApplication.run(CyberShieldApplication.class, args);
    }
}
