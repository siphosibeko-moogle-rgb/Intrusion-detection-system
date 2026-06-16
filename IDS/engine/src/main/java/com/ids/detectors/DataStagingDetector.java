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
 * Detects data staging — an internal host pulling data from many internal
 * sources in a short window, consistent with an attacker aggregating files
 * before exfiltration.
 *
 * This is BEHAVIOUR-based (how many sources contacted) not VOLUME-based (MB).
 * DataExfiltrationDetector handles volume. This handles the pattern:
 *   "workstation contacted 6 different internal servers on data ports in 2 min"
 *
 * Two checks:
 *   SOURCE SWEEP — one internal IP pulls from >= SOURCE_THRESHOLD distinct
 *      internal IPs on data ports within WINDOW_MS.
 *   PORT SWEEP ON DATA PORTS — one internal IP accesses >= PORT_THRESHOLD
 *      distinct data/storage ports on any single internal target within WINDOW_MS.
 *      (e.g. hitting SMB + FTP + DB ports on the same server = grabbing everything)
 */
public class DataStagingDetector implements Detector {

    private static final int  SOURCE_THRESHOLD = 5;           // distinct source IPs pulled from
    private static final int  PORT_THRESHOLD   = 4;           // distinct data ports on one target
    private static final long WINDOW_MS        = 120_000L;    // 2-minute window
    private static final long COOLDOWN_MS      = 30_000L;

    // Ports that carry actual data (not just control/auth)
    private static final Set<Integer> DATA_PORTS = Set.of(
            20, 21,         // FTP
            22,             // SSH / SFTP / SCP
            80, 443,        // HTTP / HTTPS
            139, 445,       // SMB
            2049,           // NFS
            3306, 5432,     // MySQL, PostgreSQL
            1433, 1521,     // SQL Server, Oracle
            27017, 6379,    // MongoDB, Redis
            9200, 9000,     // Elasticsearch, app servers
            8080, 8443      // HTTP alt
    );

    // key = collectorIP  →  map of (sourceIP → last-seen timestamp)
    private final Map<String, Map<String, Long>> sourcesContacted = new ConcurrentHashMap<>();

    // key = "collectorIP->targetIP"  →  map of (port → last-seen timestamp)
    private final Map<String, Map<Integer, Long>> portsOnTarget = new ConcurrentHashMap<>();

    private final Map<String, Long> lastAlerts = new ConcurrentHashMap<>();

    private final AlertManager alertManager;
    private final String       localSubnet;

    public DataStagingDetector(AlertManager alertManager, String localSubnet) {
        this.alertManager = alertManager;
        this.localSubnet  = localSubnet;
    }

    public void analyze(PacketContext ctx) {

        if (!ctx.isTcp() && !ctx.isUdp()) return;

        String srcIP  = ctx.getSrcIp();
        String dstIP  = ctx.getDstIp();
        String srcMac = ctx.getSrcMac();
        String dstMac = ctx.getDstMac();
        int    port   = ctx.getDstPort();
        long   now    = ctx.getTimestamp();

        if (srcIP == null || dstIP == null) return;

        // Only care about internal → internal on data ports
        if (!isInternal(srcIP) || !isInternal(dstIP)) return;
        if (!DATA_PORTS.contains(port)) return;

        //SOURCE SWEEP
        // Track how many distinct internal IPs srcIP is pulling from
        Map<String, Long> sources = sourcesContacted.computeIfAbsent(srcIP,
                k -> new ConcurrentHashMap<>());

        sources.entrySet().removeIf(e -> (now - e.getValue()) > WINDOW_MS);
        sources.put(dstIP, now);

        if (sources.size() >= SOURCE_THRESHOLD) {
            String key = "STAGE_SRC:" + srcIP;
            Long last = lastAlerts.get(key);
            if (last == null || (now - last) > COOLDOWN_MS) {
                lastAlerts.put(key, now);
                alertManager.raise(new ThreatEvent(
                        ThreatType.DATA_STAGING,
                        srcIP, srcMac, dstIP, dstMac,
                        sources.size(),
                        WINDOW_MS,
                        String.format("Data staging: %s pulled from %d internal sources in 2 min — possible pre-exfil aggregation (last: %s:%d)",
                                srcIP, sources.size(), dstIP, port),
                        Severity.HIGH,
                        ctx.isTcp() ? "TCP" : "UDP",
                        "DATA_STAGING",
                        port
                ));
                sources.clear();
            }
        }

        //PORT SWEEP ON DATA PORTS
        // Track how many distinct data ports srcIP hits on the same target
        String pairKey = srcIP + "->" + dstIP;
        Map<Integer, Long> ports = portsOnTarget.computeIfAbsent(pairKey,
                k -> new ConcurrentHashMap<>());

        ports.entrySet().removeIf(e -> (now - e.getValue()) > WINDOW_MS);
        ports.put(port, now);

        if (ports.size() >= PORT_THRESHOLD) {
            String key = "STAGE_PORT:" + pairKey;
            Long last = lastAlerts.get(key);
            if (last == null || (now - last) > COOLDOWN_MS) {
                lastAlerts.put(key, now);
                alertManager.raise(new ThreatEvent(
                        ThreatType.DATA_STAGING_MULTI_PORT,
                        srcIP, srcMac, dstIP, dstMac,
                        ports.size(),
                        WINDOW_MS,
                        String.format("Data staging: %s accessed %d data ports on %s in 2 min — possible full data grab (ports: %s)",
                                srcIP, ports.size(), dstIP, ports.keySet()),
                        Severity.HIGH,
                        ctx.isTcp() ? "TCP" : "UDP",
                        "DATA_STAGING_MULTI_PORT",
                        port
                ));
                ports.clear();
            }
        }
    }

    private boolean isInternal(String ip) {
        if (ip == null) return false;
        return ip.startsWith(localSubnet)
            || ip.startsWith("10.")
            || ip.startsWith("172.16.")
            || ip.startsWith("172.31.")
            || ip.startsWith("192.168.");
    }

    public void cleanup() {
        long now = System.currentTimeMillis();
        sourcesContacted.forEach((ip, sources) ->
                sources.entrySet().removeIf(e -> (now - e.getValue()) > WINDOW_MS));
        sourcesContacted.entrySet().removeIf(e -> e.getValue().isEmpty());

        portsOnTarget.forEach((pair, ports) ->
                ports.entrySet().removeIf(e -> (now - e.getValue()) > WINDOW_MS));
        portsOnTarget.entrySet().removeIf(e -> e.getValue().isEmpty());

        lastAlerts.entrySet().removeIf(e -> (now - e.getValue()) > COOLDOWN_MS * 4);
    }
}