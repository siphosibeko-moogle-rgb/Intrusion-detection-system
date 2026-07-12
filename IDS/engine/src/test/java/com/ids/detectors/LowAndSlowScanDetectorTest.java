package com.ids.detectors;

import com.ids.detectors.DetectorTestSupport.CapturingSink;
import com.ids.detectors.DetectorTestSupport.Packet;
import com.ids.models.ThreatEvent.ThreatType;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests the stealth-scan detector: distinct ports accumulating over a long
 * window WITH deliberate gaps (>= 1s) between probes. Defaults: 15 ports
 * over 5 minutes.
 */
class LowAndSlowScanDetectorTest {

    private static final String ATTACKER = "192.168.8.66";
    private static final String TARGET   = "192.168.8.10";
    private static final long   T0       = 1_000_000L;

    private CapturingSink sink;
    private LowAndSlowScanDetector detector;

    @BeforeEach
    void setUp() {
        sink = new CapturingSink();
        detector = new LowAndSlowScanDetector(sink, DetectorTestSupport.noTrustWhitelist());
    }

    @Test
    void slowDeliberateProbingAcrossManyPortsAlerts() {
        // 15 distinct ports, one probe every 2 seconds — under every fast-scan
        // threshold, exactly the evasion pattern this detector exists for.
        for (int i = 0; i < 15; i++) {
            detector.analyze(Packet.tcp(ATTACKER, TARGET, 2000 + i, T0 + i * 2_000L)
                .syn().build());
        }
        assertTrue(sink.raised(ThreatType.LOW_AND_SLOW_SCAN));
    }

    @Test
    void fastProbesAreLeftToTheFastScanDetector() {
        // Same 15 ports but 100ms apart — that's NmapScanDetector territory;
        // the gap check must skip them to avoid double-counting.
        for (int i = 0; i < 15; i++) {
            detector.analyze(Packet.tcp(ATTACKER, TARGET, 2000 + i, T0 + i * 100L)
                .syn().build());
        }
        assertFalse(sink.raised(ThreatType.LOW_AND_SLOW_SCAN));
    }

    @Test
    void repeatedConnectionsToFewPortsDoNotAlert() {
        // A polling client hitting the same two ports every 2s for a minute:
        // slow and sustained, but no port diversity — not a scan.
        for (int i = 0; i < 30; i++) {
            detector.analyze(Packet.tcp(ATTACKER, TARGET, 443 + (i % 2), T0 + i * 2_000L)
                .syn().build());
        }
        assertFalse(sink.raised(ThreatType.LOW_AND_SLOW_SCAN));
    }

    @Test
    void nonSynPacketsAreIgnored() {
        for (int i = 0; i < 20; i++) {
            detector.analyze(Packet.tcp(ATTACKER, TARGET, 2000 + i, T0 + i * 2_000L)
                .ack().build());
        }
        assertTrue(sink.events.isEmpty());
    }
}
