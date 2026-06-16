package com.ids.detectors;

import com.ids.alerts.AlertManager;
import com.ids.models.PacketContext;
import com.ids.models.PacketRecord;
import com.ids.models.ThreatEvent;
import com.ids.models.ThreatEvent.Severity;
import com.ids.models.ThreatEvent.ThreatType;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Detects Nmap scan patterns: SYN scan, NULL scan, FIN scan, XMAS scan,
 * UDP scan, and port sweep.
 *
 * Detection logic:
 *   - SYN scan:   SYN=1, ACK=0, FIN=0 — the most common stealth scan.
 *                 Nmap sends SYN, never completes the handshake.
 *   - NULL scan:  All TCP flags = 0. RFC says closed ports send RST.
 *                 Open ports drop the packet silently. Used to bypass
 *                 stateless firewalls.
 *   - FIN scan:   FIN only. Same RFC exploit as NULL scan.
 *   - XMAS scan:  FIN+PSH+URG set (lights up like a Christmas tree).
 *   - UDP scan:   High rate of UDP to different ports from one source.
 *   - Port sweep: Source hitting many unique destination ports — regardless
 *                 of protocol. Classic reconnaissance pattern.
 *
 * False positive risks:
 *   - SYN_THRESHOLD=15 may fire on legitimate load balancer health checks.
 *     Tune up if your environment has aggressive health checkers.
 *   - UDP threshold may fire on VOIP devices sending RTP to many ports.
 *     Whitelist known VOIP gateways.
 *
 * Implements Detector so IDSEngine can clean it up via the interface list.
 */
public class NmapScanDetector implements Detector {

    private static final int  SYN_THRESHOLD         = 15;
    private static final int  NULL_FIN_XMAS_THRESH  = 3;
    private static final int  UDP_THRESHOLD          = 10;
    private static final int  PORT_SWEEP_THRESHOLD   = 20;
    private static final long COOLDOWN_MS            = 2000L;

    // Stale eviction window: 5 minutes (300_000 ms).
    // IMPORTANT: must be long enough for LowAndSlowScanDetector to accumulate
    // evidence. The old 10s window allowed slow attackers to reset their counter
    // for free by waiting between packets.
    private static final long STALE_EVICTION_MS = 300_000L;

    private final Map<String, PacketRecord> records     = new ConcurrentHashMap<>();
    private final Map<String, Long>         lastAlerts  = new ConcurrentHashMap<>();

    private final AlertManager alertManager;

    public NmapScanDetector(AlertManager alertManager) {
        this.alertManager = alertManager;
    }

    public void analyze(PacketContext ctx) {

        if (!ctx.isTcp() && !ctx.isUdp()) return;

        String srcIP  = ctx.getSrcIp();
        String dstIP  = ctx.getDstIp();
        String srcMac = ctx.getSrcMac();
        String dstMac = ctx.getDstMac();

        if (srcIP == null) return;

        String key = srcIP;
        long   now = ctx.getTimestamp();

        PacketRecord rec = records.computeIfAbsent(key,
                k -> new PacketRecord(srcIP, srcMac));

        rec.updateMacIfBlank(srcMac);
        rec.addTimestamp(now);

        // TCP SCANS
        if (ctx.isTcp()) {

            int port = ctx.getDstPort();
            rec.addScannedPort(port, now);

            boolean syn = ctx.isSyn();
            boolean ack = ctx.isAck();
            boolean fin = ctx.isFin();
            boolean psh = ctx.isPsh();
            boolean urg = ctx.isUrg();
            boolean rst = ctx.isRst();

            // SYN SCAN
            if (syn && !ack && !fin) {
                rec.recordSyn(now);

                alert(ThreatType.NMAP_SYN_SCAN, key + ":SYN",
                        rec.getSynCount(now), SYN_THRESHOLD,
                        srcIP, srcMac, dstIP, dstMac, now, rec,
                        "Nmap SYN scan from " + srcIP,
                        Severity.HIGH, "TCP", "SYN", port);
            }

            // NULL SCAN — all flags off
            if (!syn && !ack && !fin && !psh && !urg && !rst) {
                rec.recordNull(now);

                alert(ThreatType.NMAP_NULL_SCAN, key + ":NULL",
                        rec.getNullCount(now), NULL_FIN_XMAS_THRESH,
                        srcIP, srcMac, dstIP, dstMac, now, rec,
                        "Nmap NULL scan from " + srcIP,
                        Severity.HIGH, "TCP", "NULL", port);
            }

            // FIN SCAN
            if (fin && !syn && !ack && !psh && !urg && !rst) {
                rec.recordFin(now);

                alert(ThreatType.NMAP_FIN_SCAN, key + ":FIN",
                        rec.getFinCount(now), NULL_FIN_XMAS_THRESH,
                        srcIP, srcMac, dstIP, dstMac, now, rec,
                        "Nmap FIN scan from " + srcIP,
                        Severity.HIGH, "TCP", "FIN", port);
            }

            // XMAS SCAN — FIN+PSH+URG
            if (fin && psh && urg && !syn && !ack) {
                rec.recordXmas(now);

                alert(ThreatType.NMAP_XMAS_SCAN, key + ":XMAS",
                        rec.getXmasCount(now), NULL_FIN_XMAS_THRESH,
                        srcIP, srcMac, dstIP, dstMac, now, rec,
                        "Nmap XMAS scan from " + srcIP,
                        Severity.HIGH, "TCP", "XMAS", port);
            }

        }

        // UDP SCAN
        if (ctx.isUdp()) {

            int port = ctx.getDstPort();

            rec.addScannedPort(port, now);
            rec.recordUdp(now);

            alert(ThreatType.NMAP_UDP_SCAN, key + ":UDP",
                    rec.getUdpCount(now), UDP_THRESHOLD,
                    srcIP, srcMac, dstIP, dstMac, now, rec,
                    "Nmap UDP scan from " + srcIP,
                    Severity.MEDIUM, "UDP", "UDP", port);
        }

        // PORT SWEEP — fires regardless of protocol
        if (rec.getUniquePortCount(now) >= PORT_SWEEP_THRESHOLD) {

            alert(ThreatType.NMAP_PORT_SWEEP, key + ":SWEEP",
                    rec.getUniquePortCount(now), PORT_SWEEP_THRESHOLD,
                    srcIP, srcMac, dstIP, dstMac, now, rec,
                    "Port sweep detected from " + srcIP,
                    Severity.CRITICAL, "TCP", "SWEEP", 0);
        }
    }

    private void alert(ThreatType type,
                       String alertKey,
                       int count,
                       int threshold,
                       String srcIP,
                       String srcMac,
                       String dstIP,
                       String dstMac,
                       long now,
                       PacketRecord rec,
                       String details,
                       Severity sev,
                       String protocol,
                       String reqType,
                       int port) {

        if (count < threshold) return;

        Long last = lastAlerts.get(alertKey);
        if (last != null && (now - last) < COOLDOWN_MS) return;

        lastAlerts.put(alertKey, now);

        alertManager.raise(new ThreatEvent(
                type,
                srcIP,
                srcMac,
                dstIP,
                dstMac,
                rec.getWindowCount(now),
                2000,
                details,
                sev,
                protocol,
                reqType,
                port
        ));
    }

    /**
     * Evicts PacketRecord entries that haven't been seen in 5 minutes.
     * Called by IDSEngine every 5 minutes via the Detector interface.
     *
     * Why 5 minutes: LowAndSlowScanDetector needs sustained evidence.
     * Evicting at 10s resets attacker counters silently.
     */
    @Override
    public void cleanup() {
        long now = System.currentTimeMillis();

        records.entrySet().removeIf(e ->
                now - e.getValue().getLastSeen() > STALE_EVICTION_MS
        );

        // Also prune the cooldown map to prevent unbounded growth
        lastAlerts.entrySet().removeIf(e ->
                now - e.getValue() > STALE_EVICTION_MS
        );
    }
}