package com.ids.detectors;

import com.ids.detectors.DetectorTestSupport.CapturingSink;
import com.ids.detectors.DetectorTestSupport.Packet;
import com.ids.models.ThreatEvent;
import com.ids.models.ThreatEvent.Severity;
import com.ids.models.ThreatEvent.ThreatType;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Behavioral tests for the recon detector — these pin down the exact
 * false-positive fixes that distinguish browsing from scanning:
 *
 *  1. per-(src,dst) keying: fan-out to many hosts is not a scan
 *  2. handshake-completion discount: SYNs backed by real traffic don't count
 *  3. infra-port exclusion: DNS/NTP/mDNS lookups aren't port-sweep evidence
 *
 * All tests use default thresholds (SYN=15, NULL/FIN/XMAS=3, UDP=10/4 ports,
 * sweep=20) from ids-detection.properties defaults.
 */
class NmapScanDetectorTest {

    private static final String ATTACKER = "192.168.8.66";
    private static final String TARGET   = "192.168.8.10";
    private static final long   T0       = 1_000_000L;

    private CapturingSink sink;
    private NmapScanDetector detector;

    @BeforeEach
    void setUp() {
        sink = new CapturingSink();
        detector = new NmapScanDetector(sink, DetectorTestSupport.noTrustWhitelist());
    }

    // ── The headline false-positive case ───────────────────────────────────

    @Test
    void browserFanOutToManyHostsDoesNotAlert() {
        // A page load: 30 SYNs in one second, each to a DIFFERENT host on 443,
        // each followed by an ACK + data packet (completed connections).
        for (int i = 0; i < 30; i++) {
            String host = "104.16.0." + (i + 1);
            long ts = T0 + i * 30;
            detector.analyze(Packet.tcp(ATTACKER, host, 443, ts).syn().build());
            detector.analyze(Packet.tcp(ATTACKER, host, 443, ts + 5).ack().build());
            detector.analyze(Packet.tcp(ATTACKER, host, 443, ts + 10).ack().psh().build());
        }
        assertTrue(sink.events.isEmpty(),
            "browser-style fan-out must not raise any scan alert, got: " + sink.events);
    }

    @Test
    void repeatedConnectionsToOneSiteWithCompletedHandshakesDoNotAlert() {
        // 20 connections to the SAME host (e.g. HTTP/1.1 without keep-alive),
        // every SYN followed by established traffic.
        for (int i = 0; i < 20; i++) {
            long ts = T0 + i * 50;
            detector.analyze(Packet.tcp(ATTACKER, TARGET, 443, ts).syn().build());
            detector.analyze(Packet.tcp(ATTACKER, TARGET, 443, ts + 5).ack().build());
            detector.analyze(Packet.tcp(ATTACKER, TARGET, 443, ts + 10).ack().psh().build());
        }
        assertFalse(sink.raised(ThreatType.NMAP_SYN_SCAN),
            "completed handshakes must offset the SYN count");
    }

    // ── Real scans still fire ───────────────────────────────────────────────

    @Test
    void halfOpenSynScanAlerts() {
        // nmap -sS: 16 SYN-only probes to one host, never an ACK back out.
        for (int i = 0; i < 16; i++) {
            detector.analyze(Packet.tcp(ATTACKER, TARGET, 8000 + i, T0 + i * 20)
                .syn().build());
        }
        assertTrue(sink.raised(ThreatType.NMAP_SYN_SCAN),
            "16 half-open SYNs to one host must alert (threshold 15)");
        ThreatEvent e = sink.ofType(ThreatType.NMAP_SYN_SCAN).get(0);
        assertEquals(Severity.MEDIUM, e.getSeverity(), "SYN scan is recon → MEDIUM");
        assertEquals("T1046", e.getMitreAttack());
        assertEquals("NmapScanDetector", e.getDetectedBy());
        assertTrue(e.getConfidenceScore() >= 70,
            "at/above threshold should carry >= 70 confidence");
    }

    @Test
    void nullScanAlertsHighSeverity() {
        for (int i = 0; i < 3; i++) {
            detector.analyze(Packet.tcp(ATTACKER, TARGET, 100 + i, T0 + i * 20).build());
        }
        assertTrue(sink.raised(ThreatType.NMAP_NULL_SCAN));
        ThreatEvent e = sink.ofType(ThreatType.NMAP_NULL_SCAN).get(0);
        assertEquals(Severity.HIGH, e.getSeverity(),
            "crafted-flag scans keep HIGH severity");
        assertTrue(e.getConfidenceScore() > 80,
            "crafted flags never occur legitimately → high confidence");
    }

    @Test
    void xmasScanAlerts() {
        for (int i = 0; i < 3; i++) {
            detector.analyze(Packet.tcp(ATTACKER, TARGET, 200 + i, T0 + i * 20)
                .fin().psh().urg().build());
        }
        assertTrue(sink.raised(ThreatType.NMAP_XMAS_SCAN));
    }

    @Test
    void portSweepAlertsEvenWhenHandshakesComplete() {
        // nmap -sT (connect scan) completes handshakes, so the SYN-discount
        // must NOT hide it — port diversity is the sweep signal.
        for (int i = 0; i < 25; i++) {
            long ts = T0 + i * 20;
            detector.analyze(Packet.tcp(ATTACKER, TARGET, 1000 + i, ts).syn().build());
            detector.analyze(Packet.tcp(ATTACKER, TARGET, 1000 + i, ts + 5).ack().build());
        }
        assertTrue(sink.raised(ThreatType.NMAP_PORT_SWEEP),
            "25 unique ports on one host in 2s must alert (threshold 20)");
        assertEquals(Severity.HIGH,
            sink.ofType(ThreatType.NMAP_PORT_SWEEP).get(0).getSeverity());
    }

    @Test
    void udpScanAcrossManyPortsAlerts() {
        // 12 UDP probes across 6 distinct ports in one window.
        for (int i = 0; i < 12; i++) {
            detector.analyze(Packet.udp(ATTACKER, TARGET, 7000 + (i % 6), T0 + i * 20)
                .build());
        }
        assertTrue(sink.raised(ThreatType.NMAP_UDP_SCAN));
    }

    // ── Legitimate traffic shapes that used to false-positive ──────────────

    @Test
    void dnsBurstDoesNotAlertUdpScan() {
        // 40 rapid DNS queries to the local resolver: high UDP rate, but
        // port 53 is an infra query port and only ONE distinct port anyway.
        for (int i = 0; i < 40; i++) {
            detector.analyze(Packet.udp(ATTACKER, "192.168.8.1", 53, T0 + i * 10)
                .build());
        }
        assertFalse(sink.raised(ThreatType.NMAP_UDP_SCAN),
            "a DNS burst is not a UDP scan");
        assertFalse(sink.raised(ThreatType.NMAP_PORT_SWEEP));
    }

    @Test
    void infraQueryPortsDoNotCountTowardPortSweep() {
        // Router doing double duty: DNS + DHCP + NTP + mDNS + NetBIOS from
        // one client to one host, plus a handful of normal app ports —
        // infra ports must not push the unique-port count over the line.
        int[] infraPorts = {53, 67, 68, 123, 137, 138, 1900, 5353};
        long ts = T0;
        for (int round = 0; round < 3; round++) {
            for (int port : infraPorts) {
                detector.analyze(Packet.udp(ATTACKER, "192.168.8.1", port, ts += 10).build());
            }
        }
        assertFalse(sink.raised(ThreatType.NMAP_UDP_SCAN));
        assertFalse(sink.raised(ThreatType.NMAP_PORT_SWEEP));
    }

    @Test
    void dnsServerRepliesDoNotCountAsScan() {
        // A DNS server answering many clients: source port 53, destination
        // port = each client's ephemeral port (all different). Structurally
        // identical to a UDP sweep unless service-reply ports are excluded.
        for (int i = 0; i < 30; i++) {
            detector.analyze(Packet.udp("192.168.8.1", ATTACKER, 40_000 + i, T0 + i * 10)
                .srcPort(53).build());
        }
        assertFalse(sink.raised(ThreatType.NMAP_UDP_SCAN));
        assertFalse(sink.raised(ThreatType.NMAP_PORT_SWEEP));
    }

    @Test
    void cooldownSuppressesDuplicateAlerts() {
        // Two full bursts inside one cooldown window → exactly one alert.
        for (int i = 0; i < 32; i++) {
            detector.analyze(Packet.tcp(ATTACKER, TARGET, 8000 + i, T0 + i * 10)
                .syn().build());
        }
        assertEquals(1, sink.ofType(ThreatType.NMAP_SYN_SCAN).size(),
            "cooldown must dedupe repeat alerts within 2s");
    }
}
