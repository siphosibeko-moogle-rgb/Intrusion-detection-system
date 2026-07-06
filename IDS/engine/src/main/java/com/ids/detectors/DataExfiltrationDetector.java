package com.ids.detectors;

import com.ids.alerts.AlertManager;
import com.ids.models.PacketContext;
import com.ids.models.PacketRecord;
import com.ids.models.ThreatEvent;
import com.ids.models.ThreatEvent.Severity;
import com.ids.models.ThreatEvent.ThreatType;
import com.ids.network.NetworkWhitelist;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Detection 6 — Data Exfiltration and Large Transfer Detector.
 *
 * Handles both STATIC (server) and DYNAMIC (DHCP workstation) IPs:
 * - Static servers are listed under server.N in ids-whitelist.properties,
 *   read via NetworkWhitelist.isKnownServer() / getInternalServers().
 *   FIX: this used to be dead — DataExfiltrationDetector kept its own
 *   Set<String> populated from NetworkWhitelist.getInternalServers(),
 *   which was hardcoded to always return an empty list. isKnownServer()
 *   was therefore always false, and the "(dynamic/DHCP device)" label in
 *   every alert was always appended — even when the far end was actually
 *   another known static server. NetworkWhitelist now actually parses
 *   server.N properties (see that class), so this works for real.
 * - Dynamic workstations are in the subnet but NOT listed as servers
 *
 * FIX: also switched isInternal() to NetworkWhitelist.isInternal(), which
 * correctly covers the full 172.16.0.0/12 private range. The old local
 * check here only tested ip.startsWith("172.16.") and ip.startsWith(
 * "172.31.") — the two boundary /16s — silently missing 172.17.x through
 * 172.30.x, which is Docker's/Kubernetes' default bridge/overlay range.
 * Traffic from containers on that range was invisible to this detector.
 *
 * Three alerts:
 * BULK_DOWNLOAD — dynamic device pulls > 50 MB from a static server in 60s
 * DATA_EXFILTRATION — internal device uploads > 10 MB to an external IP in 60s
 * SUSTAINED_LARGE_TRANSFER — any single flow exceeds 200 MB total
 *
 * TUNING NOTE (not changed here, needs real traffic data first):
 * all three thresholds below were audited as likely too low for a modern
 * network with cloud backup, video calls, and SaaS collaboration tools —
 * see the false-positive audit writeup. Raising them needs a baseline
 * measurement of your actual normal traffic, not a guess, so that's a
 * follow-up rather than something bundled into this fix.
 */
public class DataExfiltrationDetector implements Detector {

    private static final long BULK_THRESHOLD = 50L * 1024 * 1024; // 50 MB / 60s
    private static final long EXFIL_THRESHOLD = 10L * 1024 * 1024; // 10 MB / 60s
    private static final long SUSTAINED_THRESHOLD = 200L * 1024 * 1024; // 200 MB total
    private static final long ALERT_COOLDOWN = 30_000L;

    // Traffic FROM these ports = a server is pushing data to a client
    private static final Set<Integer> SERVER_PORTS = Set.of(
        80, 443, 8080, 8443, // HTTP / HTTPS
        21, 22, 990, // FTP, SFTP
        445, 139, // SMB / Windows file shares
        2049, // NFS
        3306, 5432, 1433, 1521, // MySQL, PostgreSQL, SQL Server, Oracle
        27017, 6379, // MongoDB, Redis
        9000, 9200 // App servers / Elasticsearch
    );

    // Per-flow PacketRecord: key = "srcIP→dstIP"
    private final Map<String, PacketRecord> flows = new ConcurrentHashMap<>();
    private final Map<String, Long> lastAlerts = new ConcurrentHashMap<>();

    private final AlertManager alertManager;
    private final NetworkWhitelist whitelist;

    public DataExfiltrationDetector(AlertManager alertManager, NetworkWhitelist whitelist) {
        this.alertManager = alertManager;
        this.whitelist = whitelist;
    }

    public void analyze(PacketContext ctx) {

        if (ctx == null) {
            return;
        }

        String srcIP = ctx.getSrcIp();
        String dstIP = ctx.getDstIp();

        String srcMac = ctx.getSrcMac();
        String dstMac = ctx.getDstMac();

        int srcPort = ctx.getSrcPort();
        int dstPort = ctx.getDstPort();

        int payloadBytes = ctx.getPayloadLength();

        if (payloadBytes <= 0) {
            return;
        }

        long now = System.currentTimeMillis();

        boolean srcInt = whitelist.isInternal(srcIP);
        boolean dstInt = whitelist.isInternal(dstIP);

        boolean srcServer =
            whitelist.isKnownServer(srcIP)
            || SERVER_PORTS.contains(srcPort);

        // Bulk download: static server → dynamic workstation
        if (srcInt && dstInt && srcServer) {

            PacketRecord rec = flows.computeIfAbsent(
                srcIP + "→" + dstIP,
                k -> new PacketRecord(srcIP, srcMac));

            rec.addBytes(payloadBytes, true, now);

            long windowBytes = rec.getWindowInboundBytes(now);

            if (windowBytes >= BULK_THRESHOLD) {

                String alertKey = "BULK:" + dstIP + "←" + srcIP;

                if (shouldAlert(alertKey, now)) {

                    boolean isDynamic = !whitelist.isKnownServer(dstIP);

                    alertManager.raise(new ThreatEvent(
                        ThreatType.BULK_DOWNLOAD,
                        dstIP,
                        dstMac,
                        srcIP,
                        srcMac,
                        rec.getTotalPacketCount(),
                        60_000L,
                        "Bulk download: " + dstIP + " [" + dstMac + "]"
                        + (isDynamic ? " (dynamic/DHCP device)" : "")
                        + " downloaded " + humanBytes(windowBytes)
                        + " from server " + srcIP
                        + " (port " + srcPort + ") in 60s"
                        + " — session total: "
                        + humanBytes(rec.getTotalSessionBytes()),
                        windowBytes > BULK_THRESHOLD * 4
                        ? Severity.CRITICAL
                        : Severity.HIGH,
                        ctx.getProtocol(),
                        "BULK_DOWNLOAD",
                        srcPort));
                }
            }
        }

        // Data exfiltration: internal → external
        if (srcInt && !dstInt) {

            PacketRecord rec = flows.computeIfAbsent(
                "EXT:" + srcIP + "→" + dstIP,
                k -> new PacketRecord(srcIP, srcMac));

            rec.addBytes(payloadBytes, false, now);

            long windowBytes = rec.getWindowOutboundBytes(now);

            if (windowBytes >= EXFIL_THRESHOLD) {

                String alertKey = "EXFIL:" + srcIP + "→" + dstIP;

                if (shouldAlert(alertKey, now)) {

                    boolean isDynamic = !whitelist.isKnownServer(srcIP);

                    alertManager.raise(new ThreatEvent(
                        ThreatType.DATA_EXFILTRATION,
                        srcIP,
                        srcMac,
                        dstIP,
                        dstMac,
                        rec.getTotalPacketCount(),
                        60_000L,
                        "Data exfiltration: " + srcIP + " [" + srcMac + "]"
                        + (isDynamic ? " (dynamic/DHCP device)" : "")
                        + " uploaded " + humanBytes(windowBytes)
                        + " to EXTERNAL host "
                        + dstIP
                        + " (port " + dstPort + ") in 60s",
                        windowBytes > EXFIL_THRESHOLD * 10
                        ? Severity.CRITICAL
                        : Severity.HIGH,
                        ctx.getProtocol(),
                        "UPLOAD",
                        dstPort));
                }
            }
        }

        // Sustained transfer
        if (srcInt || dstInt) {

            PacketRecord rec = flows.computeIfAbsent(
                "SUS:" + srcIP + ":" + dstIP,
                k -> new PacketRecord(srcIP, srcMac));

            rec.addBytes(payloadBytes, dstInt, now);

            if (rec.getTotalSessionBytes() >= SUSTAINED_THRESHOLD) {

                String alertKey = "SUSTAINED:" + srcIP + ":" + dstIP;

                if (shouldAlert(alertKey, now)) {

                    String actor =
                        srcInt ? srcIP : dstIP;

                    String actorMac =
                        srcInt ? srcMac : dstMac;

                    alertManager.raise(new ThreatEvent(
                        ThreatType.SUSTAINED_LARGE_TRANSFER,
                        actor,
                        actorMac,
                        srcInt ? dstIP : srcIP,
                        srcInt ? dstMac : srcMac,
                        rec.getTotalPacketCount(),
                        rec.getSessionDurationMs(),
                        "Sustained large transfer: "
                        + actor
                        + " ["
                        + actorMac
                        + "] — "
                        + humanBytes(rec.getTotalSessionBytes())
                        + " total over "
                        + humanDuration(
                            rec.getSessionDurationMs()),
                        Severity.HIGH,
                        ctx.getProtocol(),
                        "SUSTAINED",
                        dstPort));
                }
            }
        }
    }

    //Helpers

    private boolean shouldAlert(String key, long now) {
        Long last = lastAlerts.get(key);
        if (last == null || (now - last) > ALERT_COOLDOWN) { lastAlerts.put(key, now); return true; }
        return false;
    }

    private String humanBytes(long b) {
        if (b >= 1024L*1024*1024) return String.format("%.1f GB", b/(1024.0*1024*1024));
        if (b >= 1024L*1024) return String.format("%.1f MB", b/(1024.0*1024));
        if (b >= 1024L) return String.format("%.1f KB", b/1024.0);
        return b + " B";
    }

    private String humanDuration(long ms) {
        if (ms >= 3_600_000) return String.format("%.1f hours", ms/3_600_000.0);
        if (ms >= 60_000) return String.format("%.1f minutes", ms/60_000.0);
        return String.format("%.1f seconds", ms/1000.0);
    }

    public void cleanup() {
        long now = System.currentTimeMillis();
        flows.entrySet().removeIf(e -> (now - e.getValue().getLastSeen()) > 600_000L);
        lastAlerts.entrySet().removeIf(e -> (now - e.getValue()) > 120_000L);
    }
}