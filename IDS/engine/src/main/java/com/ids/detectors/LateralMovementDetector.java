package com.ids.detectors;

import com.ids.alerts.AlertManager;
import com.ids.models.PacketContext;
import com.ids.models.ThreatEvent;
import com.ids.models.ThreatEvent.Severity;
import com.ids.models.ThreatEvent.ThreatType;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Detects lateral movement — an internal host making new connections to many
 * other internal hosts on admin/sensitive ports within a short window.
 *
 * Logic:
 *   If a srcIP hits >= UNIQUE_HOST_THRESHOLD distinct internal IPs on sensitive
 *   ports within WINDOW_MS, raise LATERAL_MOVEMENT.
 */
public class LateralMovementDetector implements Detector {

    private static final int  UNIQUE_HOST_THRESHOLD = 5;
    private static final long WINDOW_MS             = 30_000L;
    private static final long COOLDOWN_MS           = 30_000L;

    private static final Set<Integer> SENSITIVE_PORTS = Set.of(
            22,    // SSH
            23,    // Telnet
            135,   // RPC
            139,   // NetBIOS
            445,   // SMB
            3389,  // RDP
            5900,  // VNC
            5985,  // WinRM HTTP
            5986   // WinRM HTTPS
    );

    // key = srcIP  →  map of dstIP → last-seen timestamp
    private final Map<String, Map<String, Long>> contactMap = new ConcurrentHashMap<>();
    private final Map<String, Long>              lastAlerts = new ConcurrentHashMap<>();

    private final AlertManager alertManager;
    private final String       localSubnet;   // e.g. "192.168.1."

    public LateralMovementDetector(AlertManager alertManager, String localSubnet) {
        this.alertManager = alertManager;
        this.localSubnet  = localSubnet;
    }

    public void analyze(PacketContext ctx) {

        if (!ctx.isTcp()) return;
        if (!ctx.isSyn() || ctx.isAck()) return;  // new connections only

        String srcIP  = ctx.getSrcIp();
        String dstIP  = ctx.getDstIp();
        String srcMac = ctx.getSrcMac();
        String dstMac = ctx.getDstMac();
        int    port   = ctx.getDstPort();
        long   now    = ctx.getTimestamp();

        if (srcIP == null || dstIP == null) return;
        if (!srcIP.startsWith(localSubnet) || !dstIP.startsWith(localSubnet)) return;
        if (!SENSITIVE_PORTS.contains(port)) return;

        Map<String, Long> contacts = contactMap.computeIfAbsent(srcIP, k -> new ConcurrentHashMap<>());

        contacts.entrySet().removeIf(e -> (now - e.getValue()) > WINDOW_MS);
        contacts.put(dstIP, now);

        if (contacts.size() >= UNIQUE_HOST_THRESHOLD) {

            Long last = lastAlerts.get(srcIP);
            if (last != null && (now - last) < COOLDOWN_MS) return;

            lastAlerts.put(srcIP, now);

            alertManager.raise(new ThreatEvent(
                    ThreatType.LATERAL_MOVEMENT,
                    srcIP, srcMac, dstIP, dstMac,
                    contacts.size(),
                    WINDOW_MS,
                    String.format("Lateral movement from %s → %d internal hosts on sensitive ports (last: %s:%d)",
                            srcIP, contacts.size(), dstIP, port),
                    Severity.CRITICAL,
                    "TCP", "SYN",
                    port
            ));

            contacts.clear();
        }
    }

    public void cleanup() {
        long now = System.currentTimeMillis();
        contactMap.forEach((ip, contacts) ->
                contacts.entrySet().removeIf(e -> (now - e.getValue()) > WINDOW_MS));
        contactMap.entrySet().removeIf(e -> e.getValue().isEmpty());
        lastAlerts.entrySet().removeIf(e -> (now - e.getValue()) > COOLDOWN_MS * 2);
    }
}