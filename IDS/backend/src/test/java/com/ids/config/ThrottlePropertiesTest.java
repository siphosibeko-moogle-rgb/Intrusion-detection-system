package com.ids.config;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ThrottlePropertiesTest {

    @Test
    void detectorOverrideWinsAndPartialOverrideFallsBackPerField() {
        ThrottleProperties props = new ThrottleProperties(
            new ThrottleProperties.Policy(Duration.ofMinutes(10), 5),
            Map.of("BRUTE_FORCE", new ThrottleProperties.Policy(Duration.ofMinutes(1), null)));

        assertEquals(Duration.ofMinutes(1), props.getWindow("BRUTE_FORCE"));
        // threshold not overridden -> falls back to the configured default, not the hardcoded one
        assertEquals(5, props.getThreshold("BRUTE_FORCE"));

        assertEquals(Duration.ofMinutes(10), props.getWindow("PORT_SCAN"));
        assertEquals(5, props.getThreshold("PORT_SCAN"));
    }

    @Test
    void hardcodedFallbacksWhenNothingConfigured() {
        ThrottleProperties props = new ThrottleProperties(null, Map.of());

        assertEquals(Duration.ofMinutes(10), props.getWindow("ANY"));
        assertEquals(5, props.getThreshold("ANY"));
        assertEquals(Duration.ofMinutes(10), props.maxWindow());
    }

    @Test
    void maxWindowIsLargestOfDefaultAndOverrides() {
        ThrottleProperties props = new ThrottleProperties(
            new ThrottleProperties.Policy(Duration.ofMinutes(10), 5),
            Map.of("SLOW_SCAN", new ThrottleProperties.Policy(Duration.ofHours(1), null),
                   "BRUTE_FORCE", new ThrottleProperties.Policy(Duration.ofMinutes(1), 3)));

        assertEquals(Duration.ofHours(1), props.maxWindow());
    }
}
