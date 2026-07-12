package com.ids.detectors;

import com.ids.alerts.AlertSink;
import com.ids.models.PacketContext;
import com.ids.models.ThreatEvent;
import com.ids.models.ThreatEvent.Severity;
import com.ids.models.ThreatEvent.ThreatType;
import com.ids.network.NetworkWhitelist;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Detects lateral movement — an internal host making new connections to many
 * other internal hosts on admin/sensitive ports within a short window.
 *
 * Logic:
 * If a srcIP hits >= UNIQUE_HOST_THRESHOLD distinct internal IPs on sensitive
 * ports within WINDOW_MS, raise LATERAL_MOVEMENT.
 *
 * FALSE POSITIVE RISK — read before deploying:
 * "One host touching 5+ others on SSH/RDP/SMB/WinRM within 30 seconds" is
 * also exactly how configuration-management tooling operates — Ansible,
 * Chef, Puppet, and SaltStack all connect to many managed hosts in rapid
 * succession via SSH/WinRM as their normal, intended behavior. The same
 * applies to vulnerability scanners checking SMB/RDP/SSH reachability
 * across a fleet, and to helpdesk/remote-support tools. A careful attacker
 * doing genuine lateral movement often paces themselves specifically to
 * avoid detection like this, while legitimate automation moves fast
 * because it's supposed to — so without the trusted-host exemption below,
 * this detector is more likely to catch your own Ansible control node on
 * a routine Tuesday than a patient attacker.
 *
 * FIX: now uses NetworkWhitelist.isInternal() (was a raw
 * ip.startsWith(localSubnet) check that missed Docker/K8s subnets, the
 * same bug already fixed in AfterHoursDetector, UserBehaviorAnomalyDetector,
 * and DataExfiltrationDetector), and skips any source registered as a
 * trusted scanner/automation host via NetworkWhitelist.isTrustedScanner().
 */
public class LateralMovementDetector implements Detector {

    // Tunable via ids-detection.properties; defaults preserve prior behavior.
    private static final int UNIQUE_HOST_THRESHOLD =
        com.ids.config.DetectionTuning.getInt("lateral.host.threshold", 5);
    private static final long WINDOW_MS =
        com.ids.config.DetectionTuning.getLong("lateral.window.ms", 30_000L);
    private static final long COOLDOWN_MS = 30_000L;

    private static final Set<Integer> SENSITIVE_PORTS = Set.of(
        22, // SSH
        23, // Telnet
        135, // RPC
        139, // NetBIOS
        445, // SMB
        3389, // RDP
        5900, // VNC
        5985, // WinRM HTTP
        5986 // WinRM HTTPS
    );

    // key = srcIP → map of dstIP → last-seen timestamp
    private final Map<String, Map<String, Long>> contactMap = new ConcurrentHashMap<>();
    private final Map<String, Long> lastAlerts = new ConcurrentHashMap<>();

    private final AlertSink alertManager;
    private final NetworkWhitelist whitelist;

    public LateralMovementDetector(AlertSink alertManager, NetworkWhitelist whitelist) {
        this.alertManager = alertManager;
        this.whitelist = whitelist;
    }

    public void analyze(PacketContext ctx) {

        if (!ctx.isTcp()) return;
        if (!ctx.isSyn() || ctx.isAck()) return; // new connections only

        String srcIP = ctx.getSrcIp();
        String dstIP = ctx.getDstIp();
        String srcMac = ctx.getSrcMac();
        String dstMac = ctx.getDstMac();
        int port = ctx.getDstPort();
        long now = ctx.getTimestamp();

        if (srcIP == null || dstIP == null) return;
        if (!whitelist.isInternal(srcIP) || !whitelist.isInternal(dstIP)) return;
        if (!SENSITIVE_PORTS.contains(port)) return;

        // FIX: skip known-legitimate automation/scanner hosts before ever
        // building up contact history for them — see class doc above.
        if (whitelist.isTrustedScanner(srcIP)) return;

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