package com.cybershield.url;

import com.cybershield.intel.DomainIntelService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class DomainIntelServiceTest {

    @Test
    void registrable_domain_extraction() {
        assertThat(DomainIntelService.registrableDomain("www.google.com")).isEqualTo("google.com");
        assertThat(DomainIntelService.registrableDomain("login.secure.example.co.uk")).isEqualTo("example.co.uk");
        assertThat(DomainIntelService.registrableDomain("a.b.sbi.co.in")).isEqualTo("sbi.co.in");
        assertThat(DomainIntelService.registrableDomain("evil.tk")).isEqualTo("evil.tk");
        assertThat(DomainIntelService.registrableDomain("192.168.1.1")).isNull();
        assertThat(DomainIntelService.registrableDomain("localhost")).isNull();
    }

    @Test
    void disabled_service_never_calls_out() {
        var svc = new DomainIntelService(new ObjectMapper(), false);
        assertThat(svc.lookup("example.com")).isEmpty();
    }
}
