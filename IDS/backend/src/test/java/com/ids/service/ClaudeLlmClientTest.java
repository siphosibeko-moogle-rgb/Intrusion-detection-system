package com.ids.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.ids.config.TriageProperties;
import com.ids.dto.AlertSummaryDTO;
import com.ids.dto.TriageEvidence;
import com.ids.dto.TriageVerdict;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies the "on ANY failure, delegate to heuristic — never throw" contract
 * from a real transport failure (unreachable base-url), not a mock. No live
 * network/API key needed: connecting to a closed local port fails fast.
 */
class ClaudeLlmClientTest {

    private static TriageEvidence evidence() {
        return new TriageEvidence(
            "203.0.113.9", "PORT_SCAN", "HIGH",
            10, 1, Instant.now(), Instant.now(),
            "PORT_SCAN", "10.0.0.5", 80, "HIGH",
            List.of("TCP"), List.<AlertSummaryDTO>of(),
            10, Instant.now(), Instant.now(),
            false, false, false
        );
    }

    @Test
    void transportFailureFallsBackToHeuristicWithoutThrowing() {
        ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
        TriageProperties props = new TriageProperties(
            true, "claude", "http://127.0.0.1:1", "claude-sonnet-4-5", "dummy-key",
            15000, 20, "");

        ClaudeLlmClient client = new ClaudeLlmClient(props, new HeuristicLlmClient(), mapper);

        TriageVerdict v = assertDoesNotThrow(() -> client.classify(evidence()));

        assertEquals(HeuristicLlmClient.NAME, v.model(),
            "a transport failure must delegate to the heuristic client, not surface a Claude-branded verdict");
        assertTrue(v.confidence() >= 0 && v.confidence() <= 100);
        assertNotNull(v.classification());
    }
}
