package com.ids.detectors;

import com.ids.alerts.AlertManager;
import com.ids.models.PacketContext;
import com.ids.models.ThreatEvent;
import com.ids.models.ThreatEvent.Severity;
import com.ids.models.ThreatEvent.ThreatType;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class BruteForceDetector implements Detector {

    private static final Set<Integer> AUTH_PORTS = Set.of(
        22, // SSH
        3389, // RDP
        21, // FTP
        23 // Telnet
    );

    // Thresholds
    private static final int ATTEMPT_THRESHOLD = 10;
    private static final long WINDOW_MS = 60_000L;
    private static final long COOLDOWN_MS = 300_000L;

    // key = "srcIP:dstIP:dstPort"
    private final Map<String, List<Long>> attemptMap = new ConcurrentHashMap<>();
    private final Map<String, Long> lastAlerts = new ConcurrentHashMap<>();

    private final AlertManager alertManager;

    public BruteForceDetector(AlertManager alertManager) {
        this.alertManager = alertManager;
    }

    public void analyze(PacketContext ctx) {
        if (ctx.getSrcIp() == null || ctx.getDstIp() == null) return;

        int dstPort = ctx.getDstPort();
        if (!AUTH_PORTS.contains(dstPort)) return;

        // FIX: only count NEW connection attempts (pure SYN, matching the
        // same pattern SynFloodDetector already uses), not every packet in
        // the flow. Without this, a single long-lived legitimate SSH/RDP/
        // FTP session — an admin's interactive terminal, an SFTP transfer,
        // a chatty RDP screen update stream — generates far more than
        // ATTEMPT_THRESHOLD packets in WINDOW_MS on its own, with zero
        // actual login attempts involved. A brute force is repeated
        // AUTHENTICATION attempts, i.e. repeated new connections, not
        // general traffic volume on an auth port.
        if (!ctx.isTcp() || !ctx.isSyn() || ctx.isAck()) return;

        String srcIP = ctx.getSrcIp();
        String dstIP = ctx.getDstIp();
        String srcMac = ctx.getSrcMac();
        String dstMac = ctx.getDstMac();
        String proto = ctx.getProtocol();

        // Only flag external → internal or internal → internal (not loopback)
        if (srcIP.startsWith("127.")) return;

        long now = System.currentTimeMillis();
        String key = srcIP + ":" + dstIP + ":" + dstPort;

        List<Long> attempts =
            attemptMap.computeIfAbsent(
                key,
                k -> java.util.Collections.synchronizedList(
                    new java.util.ArrayList<>()));

        attempts.add(now);

        // Remove entries older than the window
        synchronized (attempts) {
            attempts.removeIf(ts -> (now - ts) > WINDOW_MS);
        }

        int count = attempts.size();

        if (count < ATTEMPT_THRESHOLD) {
            return;
        }

        if (!shouldAlert(key, now)) {
            return;
        }

        // Escalate severity based on count and port sensitivity
        Severity sev;
        if (count >= 50) {
            sev = Severity.CRITICAL;
        } else if (count >= 25 || dstPort == 22 || dstPort == 3389) {
            sev = Severity.HIGH;
        } else {
            sev = Severity.MEDIUM;
        }

        alertManager.raise(new ThreatEvent(
            ThreatType.BRUTE_FORCE_ATTEMPT,
            srcIP, srcMac,
            dstIP, dstMac,
            count, WINDOW_MS,
            "Brute force on port " + dstPort + ": " + srcIP + " → " + dstIP
            + " (" + count + " connection attempts/min)",
            sev,
            proto, "BRUTE_FORCE", dstPort
        ));
    }

    private boolean shouldAlert(String key, long now) {
        Long last = lastAlerts.get(key);
        if (last == null || (now - last) > COOLDOWN_MS) {
            lastAlerts.put(key, now);
            return true;
        }
        return false;
    }

    public void cleanup() {
        long now = System.currentTimeMillis();
        attemptMap.entrySet().removeIf(entry -> {
            List<Long> timestamps = entry.getValue();

            synchronized (timestamps) {
                timestamps.removeIf(ts -> (now - ts) > WINDOW_MS);

                return timestamps.isEmpty();
            }
        });
        lastAlerts.entrySet().removeIf(e ->
            now - e.getValue() > 600_000L);
    }
}