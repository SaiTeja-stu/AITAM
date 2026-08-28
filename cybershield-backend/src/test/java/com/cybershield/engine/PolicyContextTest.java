package com.cybershield.engine;

import com.cybershield.domain.ContentType;
import com.cybershield.url.UrlParts;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class PolicyContextTest {

    @Test
    void allUrls_dedupes_primary_and_embedded() {
        UrlParts u = UrlParts.parse("http://169.254.169.254/latest/meta-data/").orElseThrow();
        PolicyContext ctx = PolicyContext.builder(ContentType.URL)
                .primaryUrl(u)
                .embeddedUrls(List.of(u, u))
                .build();
        assertThat(ctx.allUrls()).hasSize(1);
    }

    @Test
    void allUrls_keeps_distinct_urls() {
        PolicyContext ctx = PolicyContext.builder(ContentType.SMS)
                .primaryUrl(UrlParts.parse("https://a.example/one").orElseThrow())
                .embeddedUrls(List.of(
                        UrlParts.parse("https://a.example/one").orElseThrow(),
                        UrlParts.parse("https://b.example/two").orElseThrow()))
                .build();
        assertThat(ctx.allUrls()).hasSize(2);
    }

    @Test
    void allUrls_empty_when_none() {
        PolicyContext ctx = PolicyContext.builder(ContentType.SMS).build();
        assertThat(ctx.allUrls()).isEmpty();
    }
}
