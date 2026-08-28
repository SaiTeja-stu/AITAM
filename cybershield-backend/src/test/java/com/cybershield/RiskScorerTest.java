package com.cybershield;

import com.cybershield.domain.RiskLevel;
import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.RiskScorer;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class RiskScorerTest {

    private final RiskScorer scorer = new RiskScorer();

    @Test
    void empty_signals_are_safe() {
        assertThat(scorer.score(List.of())).isZero();
        assertThat(scorer.level(0)).isEqualTo(RiskLevel.SAFE);
    }

    @Test
    void any_critical_signal_floors_score_at_80() {
        var s = Signal.of("MSG-02", "OTP", "asks for otp", Severity.CRITICAL, 50);
        assertThat(scorer.score(List.of(s))).isGreaterThanOrEqualTo(80);
        assertThat(scorer.level(scorer.score(List.of(s)))).isEqualTo(RiskLevel.MALICIOUS);
    }

    @Test
    void trust_offset_reduces_score() {
        var bad = Signal.of("URL-09", "no https", "http", Severity.MEDIUM, 12);
        var trust = Signal.of("URL-12", "allowlisted", "known good", Severity.TRUST, -30);
        assertThat(scorer.score(List.of(bad, trust))).isZero();
    }

    @Test
    void score_is_clamped_to_100() {
        var a = Signal.of("A", "a", "d", Severity.CRITICAL, 60);
        var b = Signal.of("B", "b", "d", Severity.CRITICAL, 60);
        assertThat(scorer.score(List.of(a, b))).isEqualTo(100);
    }

    @Test
    void level_bands_match_spec() {
        assertThat(RiskLevel.fromScore(10)).isEqualTo(RiskLevel.SAFE);
        assertThat(RiskLevel.fromScore(30)).isEqualTo(RiskLevel.SUSPICIOUS);
        assertThat(RiskLevel.fromScore(60)).isEqualTo(RiskLevel.HIGH_RISK);
        assertThat(RiskLevel.fromScore(90)).isEqualTo(RiskLevel.MALICIOUS);
        assertThat(RiskLevel.SAFE.priority()).isEqualTo("P4");
        assertThat(RiskLevel.MALICIOUS.priority()).isEqualTo("P1");
    }
}
