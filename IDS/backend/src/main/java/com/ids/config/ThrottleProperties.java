package com.ids.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.boot.context.properties.bind.Name;

import java.time.Duration;
import java.util.Map;

/**
 * Throttle tuning, bound from application.properties:
 *
 *   ids.throttle.default.window=10m
 *   ids.throttle.default.escalation-threshold=5
 *   ids.throttle.detectors.BRUTE_FORCE.window=1m          # per-detector override
 *   ids.throttle.detectors.BRUTE_FORCE.escalation-threshold=3
 *
 * Per-detector values are partial overrides: each field independently falls
 * back to the configured default, then to the hardcoded fallback (10m / 5).
 * ({@code @Name} is required because "default" is a Java keyword.)
 */
@ConfigurationProperties(prefix = "ids.throttle")
public record ThrottleProperties(
        @Name("default") Policy defaults,
        @DefaultValue Map<String, Policy> detectors) {

    private static final Duration FALLBACK_WINDOW    = Duration.ofMinutes(10);
    private static final int      FALLBACK_THRESHOLD = 5;

    /** Both fields nullable so an override may set just one of them. */
    public record Policy(Duration window, Integer escalationThreshold) { }

    public Duration getWindow(String detectorType) {
        Policy override = detectorType == null ? null : detectors.get(detectorType);
        if (override != null && override.window() != null) return override.window();
        return defaultWindow();
    }

    public int getThreshold(String detectorType) {
        Policy override = detectorType == null ? null : detectors.get(detectorType);
        if (override != null && override.escalationThreshold() != null)
            return override.escalationThreshold();
        if (defaults != null && defaults.escalationThreshold() != null)
            return defaults.escalationThreshold();
        return FALLBACK_THRESHOLD;
    }

    /** Largest configured window — used to size the cleanup horizon. */
    public Duration maxWindow() {
        Duration max = defaultWindow();
        for (Policy p : detectors.values()) {
            if (p.window() != null && p.window().compareTo(max) > 0) max = p.window();
        }
        return max;
    }

    private Duration defaultWindow() {
        return (defaults != null && defaults.window() != null)
             ? defaults.window() : FALLBACK_WINDOW;
    }
}
