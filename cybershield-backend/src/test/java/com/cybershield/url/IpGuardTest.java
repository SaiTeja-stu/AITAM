package com.cybershield.url;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.InetAddress;

import static org.assertj.core.api.Assertions.assertThat;

/** SSRF defence unit tests (security spec: SSRF - localhost, private, link-local, metadata, alt representations). */
class IpGuardTest {

    private final IpGuard guard = new IpGuard();

    @ParameterizedTest
    @ValueSource(strings = {
            "127.0.0.1", "127.0.0.53", "0.0.0.0", "10.0.0.1", "10.255.255.255",
            "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254",
            "169.254.0.1", "100.64.0.1", "100.127.255.255", "198.18.0.1"
    })
    void blocks_private_loopback_linklocal_cgnat_metadata(String ip) throws Exception {
        assertThat(guard.isBlocked(InetAddress.getByName(ip)))
                .as("must block %s", ip)
                .isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"::1", "fe80::1", "fc00::1", "fd00::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1"})
    void blocks_ipv6_internal(String ip) throws Exception {
        assertThat(guard.isBlocked(InetAddress.getByName(ip))).as("must block %s", ip).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"8.8.8.8", "1.1.1.1", "93.184.216.34"})
    void allows_public_ipv4(String ip) throws Exception {
        assertThat(guard.isBlocked(InetAddress.getByName(ip))).as("must allow %s", ip).isFalse();
    }

    @Test
    void normalises_decimal_ip() {
        assertThat(guard.normalizeNumericHost("2130706433")).isEqualTo("127.0.0.1");
    }

    @Test
    void normalises_hex_ip() {
        assertThat(guard.normalizeNumericHost("0x7f000001")).isEqualTo("127.0.0.1");
    }

    @Test
    void normalises_octal_dotted_ip() {
        assertThat(guard.normalizeNumericHost("0177.0.0.01")).isEqualTo("127.0.0.1");
    }

    @Test
    void recognises_metadata_hostnames() {
        assertThat(guard.isMetadataHostname("metadata.google.internal")).isTrue();
        assertThat(guard.isMetadataHostname("169.254.169.254")).isTrue();
        assertThat(guard.isMetadataHostname("example.com")).isFalse();
    }
}
