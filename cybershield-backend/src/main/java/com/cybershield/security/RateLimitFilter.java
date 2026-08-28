package com.cybershield.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-client-IP token-bucket rate limiting on the expensive / abusable
 * endpoints (analysis and auth). Protects against brute force and scraping.
 * Limits are configurable so tests can raise them.
 */
@Component
@Order(1)
public class RateLimitFilter extends OncePerRequestFilter {

    private final ObjectMapper objectMapper;
    private final int analyzePerMin;
    private final int authPer15Min;
    private final ConcurrentHashMap<String, Bucket> analyzeBuckets = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Bucket> authBuckets = new ConcurrentHashMap<>();

    public RateLimitFilter(ObjectMapper objectMapper,
                           @Value("${cybershield.ratelimit.analyze-per-min:60}") int analyzePerMin,
                           @Value("${cybershield.ratelimit.auth-per-15min:10}") int authPer15Min) {
        this.objectMapper = objectMapper;
        this.analyzePerMin = analyzePerMin;
        this.authPer15Min = authPer15Min;
    }

    private Bucket analyzeBucket() {
        return Bucket.builder()
                .addLimit(Bandwidth.builder().capacity(analyzePerMin)
                        .refillGreedy(analyzePerMin, Duration.ofMinutes(1)).build())
                .build();
    }

    private Bucket authBucket() {
        return Bucket.builder()
                .addLimit(Bandwidth.builder().capacity(authPer15Min)
                        .refillGreedy(authPer15Min, Duration.ofMinutes(15)).build())
                .build();
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain chain) throws ServletException, IOException {
        String path = request.getRequestURI();
        String ip = clientIp(request);
        Bucket bucket = null;

        if (path.startsWith("/api/v1/analyze") || path.startsWith("/api/v1/report")) {
            bucket = analyzeBuckets.computeIfAbsent(ip, k -> analyzeBucket());
        } else if (path.startsWith("/auth/login") || path.startsWith("/auth/register")) {
            bucket = authBuckets.computeIfAbsent(ip, k -> authBucket());
        }

        if (bucket != null && !bucket.tryConsume(1)) {
            response.setStatus(429);
            response.setContentType("application/problem+json");
            response.setHeader("Retry-After", "60");
            objectMapper.writeValue(response.getWriter(), Map.of(
                    "type", "about:blank",
                    "title", "Too Many Requests",
                    "status", 429,
                    "detail", "Rate limit exceeded. Slow down and try again shortly."));
            return;
        }
        chain.doFilter(request, response);
    }

    private String clientIp(HttpServletRequest req) {
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return req.getRemoteAddr() == null ? "unknown" : req.getRemoteAddr();
    }
}
