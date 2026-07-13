package com.ids.detectors;

import com.ids.detectors.DetectorTestSupport.CapturingSink;
import com.ids.detectors.DetectorTestSupport.Packet;
import com.ids.models.ThreatEvent.ThreatType;
import com.ids.network.NetworkWhitelist;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Focuses on the trusted_networks interaction — the main way this feature
 * could be built wrong is a provider match (isTrustedNetwork) silencing
 * beaconing detection wholesale. Suppression must require the per-range
 * suppress_beaconing flag, nothing less.
 */
class BeaconingDetectorTest {

    private static final String INFECTED_HOST = "10.0.0.5";
    private static final String CLOUDFLARE_IP = "104.16.1.1"; // inside 104.16.0.0/13
    private static final long   T0            = 1_000_000L;
    private static final long   INTERVAL_MS   = 30_000L; // zero-jitter beacon

    private CapturingSink sink;

    /** Whitelist where CLOUDFLARE_IP is a trusted network, with the
     *  beaconing-suppression flag controllable per test. */
    private NetworkWhitelist trustedNetworkWhitelist(boolean suppressBeaconing) {
        return new NetworkWhitelist() {
            @Override public boolean isTrustedBeaconDestination(String dstIP) { return false; }
            @Override public boolean isTrustedNetwork(String ip) {
                return CLOUDFLARE_IP.equals(ip);
            }
            @Override public boolean isBeaconingSuppressed(String ip) {
                return suppressBeaconing && CLOUDFLARE_IP.equals(ip);
            }
        };
    }

    @BeforeEach
    void setUp() {
        sink = new CapturingSink();
    }

    private void sendBeaconTraffic(BeaconingDetector detector) {
        // MIN_SAMPLES + 1 = 6 packets at a perfectly regular interval —
        // textbook zero-jitter beacon, well under the 10% jitter threshold.
        for (int i = 0; i < 6; i++) {
            detector.analyze(Packet.tcp(INFECTED_HOST, CLOUDFLARE_IP, 443,
                T0 + i * INTERVAL_MS).syn().build());
        }
    }

    @Test
    void trustedNetworkMembershipAloneDoesNotSuppressBeaconing() {
        // suppress_beaconing = false (the default): the destination being
        // inside a trusted provider range must NOT stop the alert — C2 hides
        // on Cloudflare/AWS/Azure precisely because defenders trust them.
        BeaconingDetector detector =
            new BeaconingDetector(sink, trustedNetworkWhitelist(false));

        sendBeaconTraffic(detector);

        assertTrue(sink.raised(ThreatType.BEACONING),
            "beacon to a trusted_networks range with suppress_beaconing=false "
            + "must still alert");
    }

    @Test
    void explicitSuppressBeaconingFlagSilencesTheRange() {
        BeaconingDetector detector =
            new BeaconingDetector(sink, trustedNetworkWhitelist(true));

        sendBeaconTraffic(detector);

        assertFalse(sink.raised(ThreatType.BEACONING),
            "suppress_beaconing=true is the explicit per-range opt-in and "
            + "must silence the beacon alert");
    }

    @Test
    void ordinaryDestinationsStillAlert() {
        // Baseline sanity: no trust anywhere, regular interval → alert.
        BeaconingDetector detector =
            new BeaconingDetector(sink, DetectorTestSupport.noTrustWhitelist());

        sendBeaconTraffic(detector);

        assertTrue(sink.raised(ThreatType.BEACONING));
    }
}
