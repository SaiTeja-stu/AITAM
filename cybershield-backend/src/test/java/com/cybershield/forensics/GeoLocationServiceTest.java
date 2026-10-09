package com.cybershield.forensics;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class GeoLocationServiceTest {

    private final GeoLocationService service = new GeoLocationService();

    @Test
    void unknownOrUnresolvableIpNeverFabricatesFixedCoordinatesOrFakeCities() {
        var geo = service.resolve("0.0.0.0");
        assertThat(geo.isPrivate()).isTrue();
        assertThat(geo.latitude()).isNull();
        assertThat(geo.longitude()).isNull();

        var nullGeo = service.resolve(null);
        assertThat(nullGeo.latitude()).isNull();
        assertThat(nullGeo.longitude()).isNull();
        assertThat(nullGeo.lookupStatus()).isEqualTo("UNAVAILABLE");

        assertThat(nullGeo.latitude()).isNull();
        assertThat(nullGeo.longitude()).isNull();
    }

    @Test
    void privateAndReservedSubnetsAreCorrectlyIdentifiedWithNullCoordinates() {
        // RFC 1918
        assertThat(service.isPrivateOrLoopback("10.0.1.25")).isTrue();
        assertThat(service.isPrivateOrLoopback("192.168.1.1")).isTrue();
        assertThat(service.isPrivateOrLoopback("172.20.5.10")).isTrue();

        // Loopback & CGNAT (RFC 6598)
        assertThat(service.isPrivateOrLoopback("127.0.0.1")).isTrue();
        assertThat(service.isPrivateOrLoopback("100.64.0.5")).isTrue();
        assertThat(service.isPrivateOrLoopback("169.254.1.1")).isTrue();

        // IPv6 loopback & ULA
        assertThat(service.isPrivateOrLoopback("::1")).isTrue();
        assertThat(service.isPrivateOrLoopback("fc00::1")).isTrue();
        assertThat(service.isPrivateOrLoopback("fd12:3456::1")).isTrue();

        var privateGeo = service.resolve("192.168.1.50");
        assertThat(privateGeo.isPrivate()).isTrue();
        assertThat(privateGeo.lookupStatus()).isEqualTo("PRIVATE_NETWORK");
        assertThat(privateGeo.latitude()).isNull();
        assertThat(privateGeo.longitude()).isNull();
    }

    @Test
    void demoFixturesAreExplicitlyFlaggedAndIsolatedFromRealLookups() {
        // Known Russian phishing sample IP
        var spb = service.resolve("91.240.118.42");
        assertThat(spb.lookupStatus()).isEqualTo("DEMO_FIXTURE");
        assertThat(spb.dataSource()).contains("Demo Sample");
        assertThat(spb.city()).isEqualTo("Saint Petersburg");
        assertThat(spb.riskReason()).contains("[Demo Sample Fixture]");

        // Known Frankfurt Tor exit sample IP
        var tor = service.resolve("185.220.101.5");
        assertThat(tor.lookupStatus()).isEqualTo("DEMO_FIXTURE");
        assertThat(tor.isTorOrProxy()).isTrue();

        // Known Lagos BEC sample IP
        var lagos = service.resolve("105.112.44.89");
        assertThat(lagos.lookupStatus()).isEqualTo("DEMO_FIXTURE");
        assertThat(lagos.country()).isEqualTo("Nigeria");

        // Broad prefix like 35.1.2.3 or 52.1.2.3 must NOT be matched to hardcoded Council Bluffs or Ashburn
        // It must NOT have lookupStatus DEMO_FIXTURE
        var gcpIp = service.resolve("35.198.0.1");
        assertThat(gcpIp.lookupStatus()).isNotEqualTo("DEMO_FIXTURE");
    }
}
