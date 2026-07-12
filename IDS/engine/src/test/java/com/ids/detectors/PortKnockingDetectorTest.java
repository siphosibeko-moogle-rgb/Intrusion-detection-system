package com.ids.detectors;

import com.ids.detectors.DetectorTestSupport.CapturingSink;
import com.ids.detectors.DetectorTestSupport.Packet;
import com.ids.models.ThreatEvent.ThreatType;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests the port-knocking detector: >= 3 distinct ports within 10s, each
 * knock spaced >= 100ms apart (deliberate, not a flood).
 */
class PortKnockingDetectorTest {

    private static final String ATTACKER = "203.0.113.50";
    private static final String TARGET   = "192.168.8.10";
    private static final long   T0       = 1_000_000L;

    private CapturingSink sink;
    private PortKnockingDetector detector;

    @BeforeEach
    void setUp() {
        sink = new CapturingSink();
        detector = new PortKnockingDetector(sink, DetectorTestSupport.noTrustWhitelist());
    }

    @Test
    void deliberateKnockSequenceAlerts() {
        // Classic knock: three chosen ports, ~300ms apart.
        int[] sequence = {7000, 8000, 9000};
        long ts = T0;
        for (int port : sequence) {
            detector.analyze(Packet.tcp(ATTACKER, TARGET, port, ts += 300).syn().build());
        }
        assertTrue(sink.raised(ThreatType.PORT_KNOCKING));
    }

    @Test
    void rapidFloodIsNotKnocking() {
        // Same three ports but 10ms apart — that's a scan/flood shape, and
        // the gap check must leave it to the scan detectors.
        int[] sequence = {7000, 8000, 9000};
        long ts = T0;
        for (int port : sequence) {
            detector.analyze(Packet.tcp(ATTACKER, TARGET, port, ts += 10).syn().build());
        }
        assertFalse(sink.raised(ThreatType.PORT_KNOCKING));
    }

    @Test
    void repeatedHitsOnOnePortDoNotAlert() {
        // A client retrying one blocked port is not a knock sequence.
        long ts = T0;
        for (int i = 0; i < 6; i++) {
            detector.analyze(Packet.tcp(ATTACKER, TARGET, 8443, ts += 500).syn().build());
        }
        assertFalse(sink.raised(ThreatType.PORT_KNOCKING));
    }
}
