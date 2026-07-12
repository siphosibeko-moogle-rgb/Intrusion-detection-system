package com.ids.detectors;

import com.ids.alerts.AlertSink;
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
 * - Port sweep: source hitting many unique ports on a SINGLE destination —
 *   regardless of protocol. Classic reconnaissance pattern. Verified against
 *   PacketRecord: this window is 2 seconds (WINDOW_2S), so 20 unique
 *   ports means 20 unique ports on one target in 2 seconds — a tight,
 *   scan-specific signal, not something ordinary browsing traffic produces
 *   (a browser touches many destinations, not many ports on one of them).
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
 * - BIGGEST real-world false positive: ordinary browsing. Loading one
 *   web page opens many parallel TCP connections within the same couple
 *   of seconds — to the page's own host, its CDN edge nodes, ad/analytics
 *   hosts, font hosts, etc. — often 15+ SYNs in well under 2 seconds, all
 *   of which complete normally and exchange real data. The SYN/NULL/FIN/
 *   XMAS counters and the port-diversity counter (used by UDP scan and
 *   port sweep) used to be keyed by source IP ALONE, so that fan-out
 *   across many unrelated, legitimate destinations was summed into the
 *   same counter as an actual scan — indistinguishable from one source
 *   hammering one target. FIX: every counter in this detector is now
 *   keyed by (srcIP, dstIP) — the same "don't sum unrelated destinations
 *   together" fix already applied to HttpAnomalyDetector's flood counter.
 *   A real Nmap run concentrates SYNs/ports against ONE target and is
 *   still caught immediately (in fact more cleanly, since it's no longer
 *   diluted by unrelated background traffic); a browser fanning out to
 *   many different external hosts on port 443 never accumulates enough
 *   signal against any single destination to trip a threshold. Horizontal
 *   host-discovery sweeps against internal infrastructure (one source,
 *   many internal targets, sensitive admin ports) are still caught by
 *   LateralMovementDetector, which is purpose-built for that shape.
 * - DNS lookups (and other routine OS/background chatter — DHCP renewal,
 *   NTP sync, mDNS/SSDP discovery) used to count toward the port-diversity
 *   signal like any other destination port. A machine resolving DNS,
 *   syncing time, and renewing a DHCP lease against the same host (e.g.
 *   a home router doing double duty) within one window could nudge the
 *   unique-port count up for reasons that have nothing to do with
 *   scanning. FIX: INFRA_QUERY_PORTS excludes these well-known client-side
 *   query ports from the scanned-port diversity count entirely.
 *
 * Implements Detector so IDSEngine can clean it up via the interface list.
 */
public class NmapScanDetector implements Detector {

    // Thresholds are tunable via ids-detection.properties (see that file for
    // per-key documentation); the second argument is the built-in default.
    private static final int SYN_THRESHOLD =
        com.ids.config.DetectionTuning.getInt("nmap.syn.threshold", 15);
    private static final int NULL_FIN_XMAS_THRESH =
        com.ids.config.DetectionTuning.getInt("nmap.nullfinxmas.threshold", 3);
    private static final int UDP_THRESHOLD =
        com.ids.config.DetectionTuning.getInt("nmap.udp.threshold", 10);
    // FIX: a real UDP port scan touches many different ports; a single
    // legitimate UDP flow (RTP, DNS, NTP) sends lots of packets but to
    // very few distinct ports. Requiring both conditions separates the two.
    private static final int MIN_UDP_UNIQUE_PORTS =
        com.ids.config.DetectionTuning.getInt("nmap.udp.unique.ports", 4);
    private static final int PORT_SWEEP_THRESHOLD =
        com.ids.config.DetectionTuning.getInt("nmap.portsweep.threshold", 20);
    private static final long COOLDOWN_MS =
        com.ids.config.DetectionTuning.getLong("nmap.cooldown.ms", 2000L);

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

 // Ports a normal client legitimately queries AS the client — DNS
 // (including the TCP fallback used for large/DNSSEC responses), DHCP
 // lease renewal, NTP time sync, NetBIOS, SSDP/mDNS local discovery.
 // Excluded from the scanned-port diversity count (addScannedPort) used
 // by the UDP-scan and port-sweep checks below, so routine background
 // OS chatter never contributes to "how many distinct ports has this
 // source touched" — that signal should mean probing, not DNS lookups.
 private static final java.util.Set<Integer> INFRA_QUERY_PORTS =
     java.util.Set.of(53, 67, 68, 123, 137, 138, 1900, 5353);

    private final Map<String, PacketRecord> records = new ConcurrentHashMap<>();
    private final Map<String, Long> lastAlerts = new ConcurrentHashMap<>();

    private final AlertSink alertManager;
    // FIX: added so both the UDP-scan and port-sweep checks can skip known,
    // authorized internal scanners instead of alerting on your own
    // vulnerability-management program every time it runs.
    private final NetworkWhitelist whitelist;

    public NmapScanDetector(AlertSink alertManager, NetworkWhitelist whitelist) {
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

        // FIX: keyed by (srcIP, dstIP), not srcIP alone — see class doc
        // "BIGGEST real-world false positive" note. This is what actually
        // separates "one source hammering one target" (a scan) from "one
        // source opening lots of parallel connections to lots of different
        // legitimate destinations" (a browser loading a page).
        String key = srcIP + "|" + dstIP;
        long now = ctx.getTimestamp();

        PacketRecord rec = records.computeIfAbsent(key,
            k -> new PacketRecord(srcIP, srcMac));

        rec.updateMacIfBlank(srcMac);
        rec.addTimestamp(now);

        // TCP SCANS
        if (ctx.isTcp()) {

            int port = ctx.getDstPort();
            // FIX: don't let routine DNS-over-TCP fallback etc. count toward
            // port-sweep diversity — see INFRA_QUERY_PORTS doc above.
            if (!INFRA_QUERY_PORTS.contains(port)) {
                rec.addScannedPort(port, now);
            }

            boolean syn = ctx.isSyn();
            boolean ack = ctx.isAck();
            boolean fin = ctx.isFin();
            boolean psh = ctx.isPsh();
            boolean urg = ctx.isUrg();
            boolean rst = ctx.isRst();

            // ESTABLISHED TRAFFIC — behavioral signal. An ACK-bearing,
            // non-SYN, non-RST packet means this source COMPLETED a handshake
            // to this destination and is exchanging real data. A half-open
            // SYN scanner (nmap -sS) never sends these: it replies RST to the
            // SYN/ACK and moves on. A browser follows every SYN with an ACK
            // plus many data packets, so its established count quickly dwarfs
            // its SYN count.
            if (ack && !syn && !rst) {
                rec.recordEstablished(now);
            }

            // SYN SCAN
            if (syn && !ack && !fin) {
                rec.recordSyn(now);

                // Discount SYNs that are backed by real application traffic:
                // only the EXCESS of new-connection attempts over established
                // activity counts toward the scan threshold. Burst page loads
                // (HTTP/1.1 without keep-alive, aggressive preconnect) send
                // many SYNs but immediately follow each with ACKs/data,
                // driving this net figure to ~0. nmap -sS produces zero
                // established packets, so its net count equals its raw SYN
                // count and detection sensitivity is unchanged. (nmap -sT,
                // which does complete handshakes, is still caught by the
                // port-sweep check below — that signal is port diversity,
                // not half-open ratio.)
                int netSynCount = Math.max(0,
                    rec.getSynCount(now) - rec.getEstablishedCount(now));

                // MEDIUM, not HIGH: a SYN scan is recon — see the severity
                // philosophy note on the ThreatType enum. NULL/FIN/XMAS below
                // stay HIGH (hand-crafted packets, never legitimate).
                alert(ThreatType.NMAP_SYN_SCAN, key + ":SYN",
                    netSynCount, SYN_THRESHOLD,
                    srcIP, srcMac, dstIP, dstMac, now, rec,
                    "Nmap SYN scan from " + srcIP,
                    Severity.MEDIUM, "TCP", "SYN", port);
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

            // FIX: don't let DNS/DHCP/NTP/mDNS queries count toward
            // port-sweep/UDP-scan diversity — see INFRA_QUERY_PORTS doc above.
            if (!INFRA_QUERY_PORTS.contains(port)) {
                rec.addScannedPort(port, now);
            }
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

            // HIGH, not CRITICAL: 20+ unique ports on one host in 2s is
            // unambiguous active probing, but still recon — CRITICAL stays
            // reserved for confirmed-impact events (see ThreatType doc).
            alert(ThreatType.NMAP_PORT_SWEEP, key + ":SWEEP",
                rec.getUniquePortCount(now), PORT_SWEEP_THRESHOLD,
                srcIP, srcMac, dstIP, dstMac, now, rec,
                "Port sweep detected from " + srcIP,
                Severity.HIGH, "TCP", "SWEEP", 0);
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

        // Confidence scales with how far past the threshold the evidence is:
        // exactly at threshold = 70 (clear signal, could still be an odd
        // burst), 2x threshold or more = 95 (unambiguous). NULL/FIN/XMAS
        // types get a +15 bump before capping — those flag combinations are
        // hand-crafted and never occur in legitimate traffic, so even a
        // bare-threshold match is near-certain.
        boolean craftedFlags = type == ThreatType.NMAP_NULL_SCAN
                || type == ThreatType.NMAP_FIN_SCAN
                || type == ThreatType.NMAP_XMAS_SCAN;
        int confidence = 70 + (25 * (count - threshold)) / Math.max(1, threshold);
        if (craftedFlags) confidence += 15;
        confidence = Math.min(95, confidence);

        String reason = String.format(
            "%d %s events vs threshold %d in 2s against single host %s"
            + (craftedFlags ? " (crafted TCP flags — no legitimate cause)" : ""),
            count, reqType, threshold, dstIP);

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
        )
        .withConfidence(confidence, reason)
        .withDetection("NmapScanDetector", "2.0"));
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