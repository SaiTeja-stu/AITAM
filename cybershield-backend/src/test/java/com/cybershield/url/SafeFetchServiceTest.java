package com.cybershield.url;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/** SSRF: the fetcher must refuse to resolve/connect to internal targets. */
class SafeFetchServiceTest {

    private final SafeFetchService fetch = new SafeFetchService(new IpGuard(), true);

    @ParameterizedTest
    @ValueSource(strings = {
            "http://127.0.0.1/", "http://localhost/", "http://0.0.0.0/",
            "http://169.254.169.254/latest/meta-data/", "http://[::1]/",
            "http://10.0.0.1/", "http://192.168.0.1/", "http://metadata.google.internal/",
            "http://2130706433/", "http://0x7f000001/"
    })
    void refuses_internal_targets(String url) {
        assertThat(fetch.resolveAndValidate(hostOf(url)))
                .as("must not validate host of %s", url)
                .isNull();
    }

    @Test
    void disabled_fetch_returns_empty() {
        SafeFetchService disabled = new SafeFetchService(new IpGuard(), false);
        assertThat(disabled.fetch("http://example.com")).isEmpty();
    }

    private String hostOf(String url) {
        return UrlParts.parse(url).map(UrlParts::host).orElse("invalid");
    }
}
