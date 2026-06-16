package com.ids.detectors;

import com.ids.alerts.AlertManager;
import com.ids.models.PacketContext;
import com.ids.models.ThreatEvent;
import com.ids.models.ThreatEvent.Severity;
import com.ids.models.ThreatEvent.ThreatType;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Detects port knocking — a technique where an attacker silently hits a
 * sequence of closed ports to trigger a hidden service (e.g. SSH on a
 * non-standard port).
 *
 * Logic:
 *   - Track closed-port SYN hits per source IP in a sliding time window.
 *   - A "knock" is a SYN to a port that receives no reply (connection rejected /
 *     no ACK back) — in practice we just watch for SYN-only packets to ports
 *     that are not part of normal traffic.
 *   - If an IP hits >= KNOCK_SEQUENCE_MIN distinct ports within WINDOW_MS,
 *     each hit spaced at least MIN_KNOCK_GAP_MS apart (deliberate, not a flood),
 *     raise a PORT_KNOCKING alert.
 */
public class PortKnockingDetector implements Detector {

    private static final int  KNOCK_SEQUENCE_MIN = 3;        // min distinct ports to count as a sequence
    private static final long WINDOW_MS          = 10_000L;  // sequence must complete within 10 s
    private static final long MIN_KNOCK_GAP_MS   = 100L;     // knocks are deliberate — not a flood
    private static final long COOLDOWN_MS        = 15_000L;  // suppress repeat alerts per IP

    // Per-source IP: ordered list of (port, timestamp) knocks within the window
    private final Map<String, List<long[]>> knockLog   = new ConcurrentHashMap<>();
    private final Map<String, Long>         lastAlerts = new ConcurrentHashMap<>();

    private final AlertManager alertManager;

    public PortKnockingDetector(AlertManager alertManager) {
        this.alertManager = alertManager;
    }

    public void analyze(PacketContext ctx) {

        // Port knocking uses TCP SYN-only packets to closed ports
        if (!ctx.isTcp()) return;
        if (!ctx.isSyn() || ctx.isAck()) return;

        String srcIP  = ctx.getSrcIp();
        String srcMac = ctx.getSrcMac();
        String dstIP  = ctx.getDstIp();
        String dstMac = ctx.getDstMac();
        int    port   = ctx.getDstPort();
        long   now    = ctx.getTimestamp();

        if (srcIP == null) return;

        List<long[]> knocks = knockLog.computeIfAbsent(srcIP,
                k -> new ArrayList<>());

        synchronized (knocks) {

            // Expire old entries outside the window
            knocks.removeIf(entry -> (now - entry[1]) > WINDOW_MS);

            // Check gap from last knock — too fast = port scan, not knocking
            if (!knocks.isEmpty()) {
                long lastKnockTime = knocks.get(knocks.size() - 1)[1];
                if ((now - lastKnockTime) < MIN_KNOCK_GAP_MS) return;
            }

            // Record this knock: [port, timestamp]
            knocks.add(new long[]{ port, now });

            // Count distinct ports in the current window
            long distinctPorts = knocks.stream()
                    .mapToLong(e -> e[0])
                    .distinct()
                    .count();

            if (distinctPorts >= KNOCK_SEQUENCE_MIN) {

                Long last = lastAlerts.get(srcIP);
                if (last != null && (now - last) < COOLDOWN_MS) return;

                lastAlerts.put(srcIP, now);

                String portSequence = buildPortSequence(knocks);

                alertManager.raise(new ThreatEvent(
                        ThreatType.PORT_KNOCKING,
                        srcIP,
                        srcMac,
                        dstIP,
                        dstMac,
                        (int) distinctPorts,
                        WINDOW_MS,
                        "Port knocking sequence from " + srcIP + " → ports: " + portSequence,
                        Severity.HIGH,
                        "TCP",
                        "SYN",
                        port
                ));

                knocks.clear();
            }
        }
    }

    private String buildPortSequence(List<long[]> knocks) {
        StringBuilder sb = new StringBuilder();
        for (long[] entry : knocks) {
            if (sb.length() > 0) sb.append(", ");
            sb.append((int) entry[0]);
        }
        return sb.toString();
    }

    public void cleanup() {
        long now = System.currentTimeMillis();
        knockLog.entrySet().removeIf(e -> {
            synchronized (e.getValue()) {
                return e.getValue().isEmpty() ||
                       e.getValue().stream().allMatch(entry -> (now - entry[1]) > WINDOW_MS);
            }
        });
        lastAlerts.entrySet().removeIf(e -> (now - e.getValue()) > COOLDOWN_MS * 2);
    }
}