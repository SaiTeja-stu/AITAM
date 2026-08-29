package com.cybershield.url;

import com.cybershield.analyze.ml.UrlFeatureExtractor;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The Java feature extractor MUST produce the same numbers as {@code ml/url_features.py}
 * (the model was trained on the Python output). Reference vectors below were generated
 * with: {@code python ml/train_url_model.py} ... {@code from url_features import vector}.
 */
class UrlFeatureParityTest {

    private static double f(String url, String name) {
        return UrlFeatureExtractor.extract(url).get(name);
    }

    @Test
    void google_is_clean() {
        Map<String, Double> m = UrlFeatureExtractor.extract("https://www.google.com");
        assertEquals(22, m.get("url_length"));
        assertEquals(14, m.get("host_length"));
        assertEquals(0, m.get("path_length"));
        assertEquals(2, m.get("num_dots"));
        assertEquals(1, m.get("is_https"));
        assertEquals(0, m.get("suspicious_keywords"));
        assertEquals(3, m.get("tld_length"));
        assertEquals(3.6635, m.get("url_entropy"), 0.001);
        assertEquals(2.8424, m.get("host_entropy"), 0.001);
    }

    @Test
    void typosquat_with_credential_path() {
        String u = "http://paypa1-verify-login.tk/webscr?cmd=_login";
        assertEquals(47, f(u, "url_length"));
        assertEquals(7, f(u, "path_length"));
        assertEquals(10, f(u, "query_length"));
        assertEquals(2, f(u, "num_hyphens"));
        assertEquals(1, f(u, "suspicious_tld"));
        assertEquals(0, f(u, "is_https"));
        assertEquals(1, f(u, "num_params"));
        assertEquals(2, f(u, "suspicious_keywords"));   // verify, login
        assertEquals(1, f(u, "hyphen_in_domain"));
    }

    @Test
    void ip_host() {
        String u = "http://192.168.10.5/account/verify";
        assertEquals(1, f(u, "has_ip"));
        assertEquals(2, f(u, "num_subdomains"));
        assertEquals(9, f(u, "num_digits"));
        assertEquals(0.75, f(u, "digit_ratio_host"), 0.001);
        assertEquals(2, f(u, "suspicious_keywords"));   // account, verify
    }

    @Test
    void deep_deceptive_subdomains() {
        String u = "https://sbi.secure.login.co.in.kxj28fh.buzz/";
        assertEquals(6, f(u, "num_dots"));
        assertEquals(5, f(u, "num_subdomains"));
        assertEquals(1, f(u, "suspicious_tld"));
        assertEquals(4.0931, f(u, "host_entropy"), 0.001);
    }

    @Test
    void at_sign_trick() {
        String u = "https://user:pass@evil.example.com/a/b?x=1&y=2";
        assertEquals(1, f(u, "has_at"));
        assertEquals(1, f(u, "num_subdomains"));
        assertEquals(2, f(u, "num_params"));
        assertEquals(4, f(u, "path_length"));
    }

    @Test
    void punycode_and_shortener() {
        assertEquals(1, f("http://xn--pple-43d.com/signin", "has_punycode"));
        assertEquals(1, f("bit.ly/abc123", "is_shortener"));
        assertEquals(0, f("https://amazon.in/dp/B0ABCDEF12", "suspicious_keywords"));
    }

    @Test
    void clean_url_scores_low_dirty_scores_high() {
        // sanity on the classifier itself if the model is present
        com.cybershield.analyze.ml.MlUrlClassifier c =
                new com.cybershield.analyze.ml.MlUrlClassifier(new com.fasterxml.jackson.databind.ObjectMapper());
        if (!c.isReady()) return;   // model file optional
        double clean = c.probability("https://www.google.com");
        double dirty = c.probability("http://paypa1-verify-login.tk/webscr?cmd=_login-run&dispatch=xyz");
        assertTrue(clean < 0.2, "clean url prob was " + clean);
        assertTrue(dirty > 0.8, "dirty url prob was " + dirty);
    }
}
