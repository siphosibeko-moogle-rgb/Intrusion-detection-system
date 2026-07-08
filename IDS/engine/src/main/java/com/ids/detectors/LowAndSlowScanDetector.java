package com.ids.detectors;

import com.ids.alerts.AlertManager;
import com.ids.models.PacketContext;
import com.ids.models.ThreatEvent;
import com.ids.models.ThreatEvent.Severity;
import com.ids.models.ThreatEvent.ThreatType;
import com.ids.network.NetworkWhitelist;

import java.util.Deque;
import java.util.Map;
import java.util.ArrayDeque;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Detects low-and-slow port scanning — an attacker who deliberately spreads
 * probes over a long window to stay below threshold-based detectors (like
 * NmapScanDetector which catches fast scans).
 *
 * Difference from NmapScanDetector:
 * NmapScanDetector: many ports in a SHORT window (seconds) → fast scan
 * LowAndSlowScanDetector: distinct ports accumulate over a LONG window (minutes)
 * with deliberate gaps between probes → stealth scan
 *
 * Logic:
 * Track SYN-only packets per srcIP over LONG_WINDOW_MS.
 * If distinct destination ports exceed SLOW_PORT_THRESHOLD within that window
 * AND the average gap between probes is > MIN_PROBE_GAP_MS (confirming it is
 * deliberately slow, not just Nmap at a different speed), raise LOW_AND_SLOW_SCAN.
 *
 * FALSE POSITIVE RISK: infrastructure monitoring tools (Nagios, Zabbix, PRTG)
 * that check service availability across many ports on a schedule, spaced a
 * few seconds apart per check cycle, are architecturally identical to what
 * this detector is built to catch. FIX: now skips known trusted
 * scanners/monitoring hosts via NetworkWhitelist.isTrustedScanner().
 */
public class LowAndSlowScanDetector implements Detector {

    private static final int SLOW_PORT_THRESHOLD = 15; // distinct ports over the long window
    private static final long LONG_WINDOW_MS = 300_000L; // 5-minute observation window
    private static final long MIN_PROBE_GAP_MS = 1_000L; // probes must be >= 1s apart (not a flood)
    private static final long COOLDOWN_MS = 60_000L;

    // key = srcIP → deque of (dstPort packed with timestamp: long[]{port, time})
    private final Map<String, Deque<long[]>> probeLog = new ConcurrentHashMap<>();
    private final Map<String, Long> lastAlerts = new ConcurrentHashMap<>();

    private final AlertManager alertManager;
    private final NetworkWhitelist whitelist;

    public LowAndSlowScanDetector(AlertManager alertManager, NetworkWhitelist whitelist) {
        this.alertManager = alertManager;
        this.whitelist = whitelist;
    }

    public void analyze(PacketContext ctx) {

        if (!ctx.isTcp()) return;
        if (!ctx.isSyn() || ctx.isAck()) return; // SYN-only = new connection attempt

        String srcIP = ctx.getSrcIp();
        String dstIP = ctx.getDstIp();
        String srcMac = ctx.getSrcMac();
        String dstMac = ctx.getDstMac();
        int port = ctx.getDstPort();
        long now = ctx.getTimestamp();

        if (srcIP == null) return;

        // FIX: skip known-legitimate scanners/monitoring hosts before ever
        // building up probe history for them — see class doc above.
        if (whitelist.isTrustedScanner(srcIP)) return;

        Deque<long[]> probes = probeLog.computeIfAbsent(srcIP, k -> new ArrayDeque<>());

        synchronized (probes) {

            // Expire entries outside the long window
            while (!probes.isEmpty() && (now - probes.peekFirst()[1]) > LONG_WINDOW_MS) {
                probes.pollFirst();
            }

            // Gap check: last probe must be at least MIN_PROBE_GAP_MS ago
            // (if faster, NmapScanDetector handles it — no double-counting)
            if (!probes.isEmpty()) {
                long lastProbeTime = probes.peekLast()[1];
                if ((now - lastProbeTime) < MIN_PROBE_GAP_MS) return;
            }

            probes.addLast(new long[]{ port, now });

            // Count distinct ports in window
            long distinctPorts = probes.stream().mapToLong(e -> e[0]).distinct().count();

            if (distinctPorts >= SLOW_PORT_THRESHOLD) {

                Long last = lastAlerts.get(srcIP);
                if (last != null && (now - last) < COOLDOWN_MS) return;

                lastAlerts.put(srcIP, now);

                // Compute average gap to confirm it is genuinely slow
                long[] arr = probes.stream().mapToLong(e -> e[1]).toArray();
                double avgGap = arr.length > 1
                    ? (double)(arr[arr.length - 1] - arr[0]) / (arr.length - 1)
                    : 0;

                alertManager.raise(new ThreatEvent(
                    ThreatType.LOW_AND_SLOW_SCAN,
                    srcIP, srcMac, dstIP, dstMac,
                    (int) distinctPorts,
                    LONG_WINDOW_MS,
                    String.format("Low-and-slow scan from %s: %d distinct ports over %.1fs (avg gap %.1fs)",
                        srcIP, distinctPorts,
                        LONG_WINDOW_MS / 1000.0,
                        avgGap / 1000.0),
                    Severity.HIGH,
                    "TCP", "SYN",
                    port
                ));

                probes.clear();
            }
        }
    }

    public void cleanup() {
        long now = System.currentTimeMillis();
        probeLog.entrySet().removeIf(e -> {
            synchronized (e.getValue()) {
                while (!e.getValue().isEmpty() && (now - e.getValue().peekFirst()[1]) > LONG_WINDOW_MS) {
                    e.getValue().pollFirst();
                }
                return e.getValue().isEmpty();
            }
        });
        lastAlerts.entrySet().removeIf(e -> (now - e.getValue()) > COOLDOWN_MS * 2);
    }
}