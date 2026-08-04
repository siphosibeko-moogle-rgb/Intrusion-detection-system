package com.ids.service;

import com.ids.dto.AlertSummaryDTO;
import com.ids.dto.TriageEvidence;
import com.ids.dto.TriageVerdict;
import com.ids.enums.TriageClassification;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class HeuristicLlmClientTest {

    private final HeuristicLlmClient client = new HeuristicLlmClient();

    private static TriageEvidence evidence(int threatScore, int occurrenceCount,
                                           boolean whitelisted, boolean trustedNetwork,
                                           boolean criticalAsset, String severity) {
        return new TriageEvidence(
            "203.0.113.9", "PORT_SCAN", severity,
            occurrenceCount, 1, Instant.now(), Instant.now(),
            "PORT_SCAN", "10.0.0.5", threatScore, "LOW",
            List.of("TCP"), List.<AlertSummaryDTO>of(),
            occurrenceCount, Instant.now(), Instant.now(),
            whitelisted, trustedNetwork, criticalAsset
        );
    }

    @Test
    void whitelistedSourceIsLikelyFalsePositiveWithoutRegardToOtherFactors() {
        TriageVerdict v = client.classify(evidence(90, 50, true, false, true, "CRITICAL"));
        assertEquals(TriageClassification.LIKELY_FALSE_POSITIVE, v.classification());
    }

    @Test
    void trustedNetworkSourceIsLikelyFalsePositive() {
        TriageVerdict v = client.classify(evidence(10, 1, false, true, false, "LOW"));
        assertEquals(TriageClassification.LIKELY_FALSE_POSITIVE, v.classification());
    }

    @Test
    void highThreatScoreIsLikelyTruePositive() {
        TriageVerdict v = client.classify(evidence(80, 1, false, false, false, "LOW"));
        assertEquals(TriageClassification.LIKELY_TRUE_POSITIVE, v.classification());
    }

    @Test
    void criticalAssetTargetedAtHighSeverityIsLikelyTruePositive() {
        TriageVerdict v = client.classify(evidence(10, 1, false, false, true, "HIGH"));
        assertEquals(TriageClassification.LIKELY_TRUE_POSITIVE, v.classification());
    }

    @Test
    void criticalAssetTargetedAtLowSeverityIsNotAutomaticallyTruePositive() {
        TriageVerdict v = client.classify(evidence(10, 1, false, false, true, "LOW"));
        assertNotEquals(TriageClassification.LIKELY_TRUE_POSITIVE, v.classification());
    }

    // Correction 3: a source with a MODEST raw alert count (totalAlerts=1,
    // simulated by threatScore staying low) but a HIGH occurrenceCount must
    // still be flagged — the throttle-aware volume signal, not raw count.
    @Test
    void highOccurrenceCountWithLowThreatScoreStillFlagsAsLikelyTruePositive() {
        TriageVerdict v = client.classify(evidence(10, 25, false, false, false, "LOW"));
        assertEquals(TriageClassification.LIKELY_TRUE_POSITIVE, v.classification());
        assertTrue(v.reasoning().contains("occurrenceCount"),
            "reasoning should cite occurrenceCount as the driving signal");
    }

    @Test
    void lowOccurrenceCountWithNoOtherSignalNeedsReview() {
        TriageVerdict v = client.classify(evidence(10, 1, false, false, false, "LOW"));
        assertEquals(TriageClassification.NEEDS_REVIEW, v.classification());
    }

    @Test
    void confidenceIsAlwaysWithinBounds() {
        for (int occ : new int[]{0, 5, 30, 100, 1000}) {
            TriageVerdict v = client.classify(evidence(0, occ, false, false, false, "LOW"));
            assertTrue(v.confidence() >= 0 && v.confidence() <= 100,
                "confidence out of range for occurrenceCount=" + occ + ": " + v.confidence());
        }
    }

    @Test
    void neverThrowsAndAlwaysFillsReasoningAndRecommendation() {
        TriageVerdict v = client.classify(evidence(0, 0, false, false, false, null));
        assertNotNull(v.reasoning());
        assertFalse(v.reasoning().isBlank());
        assertNotNull(v.recommendation());
        assertFalse(v.recommendation().isBlank());
        assertEquals(HeuristicLlmClient.NAME, v.model());
    }
}
