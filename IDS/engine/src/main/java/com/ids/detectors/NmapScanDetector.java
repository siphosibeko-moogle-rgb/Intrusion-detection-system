package com.ids.detectors;

import com.ids.alerts.AlertManager;
import com.ids.models.PacketContext;
import com.ids.models.PacketRecord;
import com.ids.models.ThreatEvent;
import com.ids.models.ThreatEvent.Severity;
import com.ids.models.ThreatEvent.ThreatType;
import com.ids.network.NetworkWhitelist;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Detects Nmap scan patterns: SYN scan, NULL scan, FIN scan, XMAS scan,
 * UDP scan, and port sweep.
 *
 * Detection logic:
 * - SYN scan: SYN=1, ACK=0, FIN=0 — the most common stealth scan.
 *   Nmap sends SYN, never completes the handshake.
 * - NULL scan: All TCP flags = 0. RFC says closed ports send RST.
 *   Open ports drop the packet silently. Used to bypass
 *   stateless firewalls.
 * - FIN scan: FIN only. Same RFC exploit as NULL scan.
 * - XMAS scan: FIN+PSH+URG set (lights up like a Christmas tree).
 * - UDP scan: high rate of UDP packets AND touching multiple distinct
 *   destination ports from one source. Both conditions are required —
 *   see the false-positive note below.
 * - Port sweep: source hitting many unique destination ports — regardless
 *   of protocol. Classic reconnaissance pattern. Verified against
 *   PacketRecord: this window is 2 seconds (WINDOW_2S), so 20 unique
 *   ports means 20 unique ports in 2 seconds — a tight, scan-specific
 *   signal, not something ordinary browsing traffic produces.
 *
 * False positive risks:
 * - SYN_THRESHOLD=15 may fire on legitimate load balancer health checks.
 *   Tune up if your environment has aggressive health checkers.
 * - UDP_THRESHOLD alone used to fire on VOIP/DNS/NTP traffic sending many
 *   packets to the SAME one or two ports repeatedly. FIX: UDP scan now
 *   also requires MIN_UDP_UNIQUE_PORTS distinct destination ports in the
 *   same 2s window — a real Nmap UDP scan touches many ports, a VOIP/RTP
 *   stream or DNS burst touches very few.
 * - Both UDP scan and port sweep will fire on YOUR OWN authorized
 *   vulnerability scanner (Nessus/OpenVAS/nmap run for compliance) —
 *   that tool behaves identically to what this detector is built to
 *   catch. FIX: both now check NetworkWhitelist.isTrustedScanner() first.
 *
 * Implements Detector so IDSEngine can clean it up via the interface list.
 */
public class NmapScanDetector implements Detector {

    private static final int SYN_THRESHOLD = 15;
    private static final int NULL_FIN_XMAS_THRESH = 3;
    private static final int UDP_THRESHOLD = 10;
    // FIX: a real UDP port scan touches many different ports; a single
    // legitimate UDP flow (RTP, DNS, NTP) sends lots of packets but to
    // very few distinct ports. Requiring both conditions separates the two.
    private static final int MIN_UDP_UNIQUE_PORTS = 4;
    private static final int PORT_SWEEP_THRESHOLD = 20;
    private static final long COOLDOWN_MS = 2000L;

    // Stale eviction window: 5 minutes (300_000 ms).
    // IMPORTANT: must be long enough for LowAndSlowScanDetector to accumulate
    // evidence. The old 10s window allowed slow attackers to reset their counter
    // for free by waiting between packets.
    private static final long STALE_EVICTION_MS = 300_000L;

 // Ports a server replies FROM, not scans FROM. A DNS/DHCP/NTP server
 // answering many clients touches a different destination port on
 // every reply (the client's ephemeral port) — structurally identical
 // to a UDP port scan unless replies from these known service ports
 // are excluded from the scan-probe count.
 private static final java.util.Set<Integer> SERVICE_REPLY_PORTS =
     java.util.Set.of(53, 67, 68, 123, 137, 138, 5353);

    private final Map<String, PacketRecord> records = new ConcurrentHashMap<>();
    private final Map<String, Long> lastAlerts = new ConcurrentHashMap<>();

    private final AlertManager alertManager;
    // FIX: added so both the UDP-scan and port-sweep checks can skip known,
    // authorized internal scanners instead of alerting on your own
    // vulnerability-management program every time it runs.
    private final NetworkWhitelist whitelist;

    public NmapScanDetector(AlertManager alertManager, NetworkWhitelist whitelist) {
        this.alertManager = alertManager;
        this.whitelist = whitelist;
    }

    public void analyze(PacketContext ctx) {

        if (!ctx.isTcp() && !ctx.isUdp()) return;

        String srcIP = ctx.getSrcIp();
        String dstIP = ctx.getDstIp();
        String srcMac = ctx.getSrcMac();
        String dstMac = ctx.getDstMac();

        if (srcIP == null) return;

        String key = srcIP;
        long now = ctx.getTimestamp();

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
        if (ctx.isUdp() && !SERVICE_REPLY_PORTS.contains(ctx.getSrcPort())) {

            int port = ctx.getDstPort();

            rec.addScannedPort(port, now);
            rec.recordUdp(now);

            // FIX: require port diversity, not just packet rate. A single
            // legitimate UDP flow (RTP call, DNS burst, NTP sync) can easily
            // send >10 packets/2s to the same one or two ports — that's not
            // scanning. A real UDP scan touches many distinct ports rapidly.
            if (!whitelist.isTrustedScanner(srcIP)
                    && rec.getUniquePortCount(now) >= MIN_UDP_UNIQUE_PORTS) {
                alert(ThreatType.NMAP_UDP_SCAN, key + ":UDP",
                    rec.getUdpCount(now), UDP_THRESHOLD,
                    srcIP, srcMac, dstIP, dstMac, now, rec,
                    "Nmap UDP scan from " + srcIP,
                    Severity.MEDIUM, "UDP", "UDP", port);
            }
        }

        // PORT SWEEP — fires regardless of protocol
        // FIX: skip known, authorized internal scanners (Nessus/OpenVAS/
        // scheduled nmap compliance scans behave identically to a real
        // attacker's port sweep — this is the same signal by design).
        if (!whitelist.isTrustedScanner(srcIP)
                && rec.getUniquePortCount(now) >= PORT_SWEEP_THRESHOLD) {

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