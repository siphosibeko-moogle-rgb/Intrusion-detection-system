package com.ids.detectors;

import com.ids.alerts.AlertManager;
import com.ids.models.PacketContext;
import com.ids.models.ThreatEvent;
import com.ids.models.ThreatEvent.Severity;
import com.ids.models.ThreatEvent.ThreatType;
import com.ids.network.NetworkWhitelist;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Detects user behaviour anomalies — an internal host acting outside its
 * established baseline within a rolling window.
 *
 * Checks:
 * 1. NEW PROTOCOL — host suddenly uses a protocol it has never used before
 * 2. NEW SENSITIVE DEST — first contact with an internal IP on a sensitive port
 * 3. BURST ACTIVITY — event rate spikes to 3x the host's rolling average
 * 4. NEW SERVICE PORT — host accesses a sensitive service port for the first time
 *
 * Baselines are in-session only (reset on restart).
 * MIN_BASELINE_EVENTS must be reached before any alert fires — prevents
 * false positives during the learning phase.
 */
public class UserBehaviorAnomalyDetector implements Detector {

    private static final long BASELINE_WINDOW_MS = 300_000L; // 5-min rolling window
    private static final long BURST_WINDOW_MS = 60_000L; // 1-min burst check
    private static final int BURST_MULTIPLIER = 3; // 3x avg/min = burst
    private static final int MIN_BASELINE_EVENTS = 10; // learn before alerting
    private static final long COOLDOWN_MS = 20_000L;

    private static final Set<Integer> SENSITIVE_PORTS = Set.of(
        22, 23, 3389, 5900, // remote access
        445, 139, 135, // SMB / RPC
        3306, 5432, 1433, 1521, // relational DBs
        27017, 6379, 9200, 2049 // NoSQL / NFS
    );

    // per srcIP
    private final Map<String, Set<String>> knownProtocols = new ConcurrentHashMap<>();
    private final Map<String, Set<String>> knownDests = new ConcurrentHashMap<>();
    private final Map<String, Set<Integer>> knownSvcPorts = new ConcurrentHashMap<>();
    private final Map<String, Deque<Long>> eventTimes = new ConcurrentHashMap<>();
    private final Map<String, Long> lastAlerts = new ConcurrentHashMap<>();

    private final AlertManager alertManager;
    // FIX: replaced the local String localSubnet + a hand-rolled isInternal()
    // with the shared NetworkWhitelist instance. The old check only tested
    // ip.startsWith("172.16.") and ip.startsWith("172.31.") — the two boundary
    // /16s of the 172.16.0.0/12 private range — silently missing 172.17.x
    // through 172.30.x, which is Docker's and Kubernetes' default bridge/
    // overlay range. Any container on that range was invisible to this
    // detector entirely (isInternal returned false, so `if (!isInternal(srcIP))
    // return;` skipped it before any analysis ran). NetworkWhitelist.isInternal()
    // covers the full range correctly and also knows about configured Docker
    // subnets, so this is a real coverage fix, not just a cleanup.
    private final NetworkWhitelist whitelist;

    public UserBehaviorAnomalyDetector(AlertManager alertManager, NetworkWhitelist whitelist) {
        this.alertManager = alertManager;
        this.whitelist = whitelist;
    }

    public void analyze(PacketContext ctx) {

        String srcIP = ctx.getSrcIp();
        String dstIP = ctx.getDstIp();
        String srcMac = ctx.getSrcMac();
        String dstMac = ctx.getDstMac();
        int port = ctx.getDstPort();
        long now = ctx.getTimestamp();

        if (srcIP == null || dstIP == null) return;
        if (!whitelist.isInternal(srcIP)) return;

        String proto = ctx.isTcp() ? "TCP" : ctx.isUdp() ? "UDP" : ctx.isIcmp() ? "ICMP" : "OTHER";
        String destKey = dstIP + ":" + port;

        // ── Maintain rolling event window ────────────────────────────────────
        Deque<Long> times = eventTimes.computeIfAbsent(srcIP, k -> new ArrayDeque<>());
        synchronized (times) {
            times.addLast(now);
            while (!times.isEmpty() && (now - times.peekFirst()) > BASELINE_WINDOW_MS) {
                times.pollFirst();
            }
        }

        int totalEvents = times.size();
        boolean hasBaseline = totalEvents >= MIN_BASELINE_EVENTS;

        Set<String> protocols = knownProtocols.computeIfAbsent(srcIP, k -> ConcurrentHashMap.newKeySet());
        Set<String> dests = knownDests.computeIfAbsent(srcIP, k -> ConcurrentHashMap.newKeySet());
        Set<Integer> svcPorts = knownSvcPorts.computeIfAbsent(srcIP, k -> ConcurrentHashMap.newKeySet());

        // ── 1. NEW PROTOCOL ──────────────────────────────────────────────────
        if (hasBaseline && !protocols.contains(proto)) {
            raise("PROTO:" + srcIP + ":" + proto, ThreatType.UBA_NEW_PROTOCOL,
                srcIP, srcMac, dstIP, dstMac, now,
                "UBA — new protocol: " + srcIP + " used " + proto + " for first time (→ " + dstIP + ":" + port + ")",
                Severity.MEDIUM, proto, port);
        }
        protocols.add(proto);

        // ── 2. NEW SENSITIVE DESTINATION ────────────────────────────────────
        if (hasBaseline && SENSITIVE_PORTS.contains(port) && !dests.contains(destKey) && whitelist.isInternal(dstIP)) {
            raise("NEWDEST:" + srcIP + ":" + destKey, ThreatType.UBA_NEW_DESTINATION,
                srcIP, srcMac, dstIP, dstMac, now,
                "UBA — new sensitive destination: " + srcIP + " → " + dstIP + ":" + port + " (first contact)",
                Severity.MEDIUM, proto, port);
        }
        dests.add(destKey);

        // ── 3. BURST ACTIVITY ────────────────────────────────────────────────
        if (hasBaseline) {
            long recentCount;
            synchronized (times) {
                recentCount = times.stream().filter(t -> (now - t) <= BURST_WINDOW_MS).count();
            }
            double avgPer60s = (double) totalEvents / (BASELINE_WINDOW_MS / 60_000.0);
            if (avgPer60s > 2 && recentCount >= BURST_MULTIPLIER * avgPer60s) {
                raise("BURST:" + srcIP, ThreatType.UBA_BURST_ACTIVITY,
                    srcIP, srcMac, dstIP, dstMac, now,
                    String.format("UBA — burst activity: %s sent %d events/min vs %.1f avg/min (%.1fx normal)",
                        srcIP, recentCount, avgPer60s, recentCount / avgPer60s),
                    Severity.HIGH, proto, port);
            }
        }

        // ── 4. NEW SERVICE PORT ──────────────────────────────────────────────
        if (hasBaseline && SENSITIVE_PORTS.contains(port) && !svcPorts.contains(port)) {
            raise("SVCPORT:" + srcIP + ":" + port, ThreatType.UBA_NEW_SERVICE_PORT,
                srcIP, srcMac, dstIP, dstMac, now,
                "UBA — new service port: " + srcIP + " accessed port " + port + " for first time (→ " + dstIP + ")",
                Severity.MEDIUM, proto, port);
        }
        svcPorts.add(port);
    }

    private void raise(String key, ThreatType type,
                        String srcIP, String srcMac,
                        String dstIP, String dstMac,
                        long now, String details,
                        Severity sev, String proto, int port) {
        Long last = lastAlerts.get(key);
        if (last != null && (now - last) < COOLDOWN_MS) return;
        lastAlerts.put(key, now);
        alertManager.raise(new ThreatEvent(
            type, srcIP, srcMac, dstIP, dstMac,
            1, BASELINE_WINDOW_MS, details, sev, proto, "UBA", port
        ));
    }

    public void cleanup() {
        long now = System.currentTimeMillis();
        eventTimes.forEach((ip, times) -> {
            synchronized (times) {
                while (!times.isEmpty() && (now - times.peekFirst()) > BASELINE_WINDOW_MS) {
                    times.pollFirst();
                }
            }
        });
        eventTimes.entrySet().removeIf(e -> {
            synchronized (e.getValue()) { return e.getValue().isEmpty(); }
        });
        lastAlerts.entrySet().removeIf(e -> (now - e.getValue()) > COOLDOWN_MS * 4);
    }
}