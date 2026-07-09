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
 * Detects DNS Tunneling, DNS Flood, and DNS Amplification.
 */
public class DnsTunnelingDetector implements Detector {
	
	
    private static final int DNS_PORT = 53;
    private static final int FLOOD_THRESHOLD = 20;
    private static final int UNIQUE_SUB_THRESH = 15;
    private static final double HIGH_ENTROPY = 4.3;
    private static final long COOLDOWN_MS = 10_000L;
    private static final int AMPLIFICATION_SIZE_THRESHOLD = 512;

    private final Map<String, PacketRecord> records = new ConcurrentHashMap<>();
    private final Map<String, Long> lastAlerts = new ConcurrentHashMap<>();
    private final AlertManager alertManager;

    public DnsTunnelingDetector(AlertManager alertManager) {
        this.alertManager = alertManager;
    }

    public void analyze(PacketContext ctx, byte[] udpPayload) {

        //Only DNS traffic
        if (!(ctx.isUdp() || ctx.isTcp())) return;
        if (ctx.getSrcPort() != DNS_PORT && ctx.getDstPort() != DNS_PORT) return;

        String srcIP = ctx.getSrcIp();
        String dstIP = ctx.getDstIp();
        String srcMac = ctx.getSrcMac();
        String dstMac = ctx.getDstMac();
        long now = ctx.getTimestamp();

        if (srcIP == null || srcMac == null) return;

        String key = srcIP + ":" + srcMac;

        PacketRecord rec = records.computeIfAbsent(key,
                k -> new PacketRecord(srcIP, srcMac));

        rec.addTimestamp(now);
        rec.incrementDnsQuery();

        int windowCount = rec.getWindowCount(now);
        long winMs = rec.getWindowDurationMs(now);

        // DNS FLOOD DETECTION
        if (windowCount >= FLOOD_THRESHOLD) {
            alert(ThreatType.DNS_FLOOD, key + ":FLOOD", now,
                    srcIP, srcMac, dstIP, dstMac,
                    "DNS flood: " + windowCount + " queries in short time",
                    Severity.HIGH, windowCount, winMs, ctx.getProtocol(), DNS_PORT);
        }
        // DNS TUNN
        String domain = extractDomain(udpPayload);
        if (domain != null) {

            rec.addDnsSubdomain(domain);

            // Measure entropy on the leftmost label only (e.g. "signaler-pa"
            // in "signaler-pa.clients6.google.com"), not the full FQDN.
            // Attackers stuff encoded data into the subdomain they control;
            // the domain/TLD portion is always ordinary English/ASCII and
            // dilutes a real tunnel's entropy score toward normal-looking
            // values when measured over the whole string — which is exactly
            // why ordinary Google/Mozilla telemetry hostnames were tripping
            // this at the old 3.8 threshold.
            String leftmostLabel = firstLabel(domain);
            double entropy = shannonEntropy(leftmostLabel);

            // Long + high entropy = suspicious
            if (domain.length() > 40 || entropy > HIGH_ENTROPY) {

                Severity sev = entropy > 4.5
                        ? Severity.CRITICAL
                        : entropy > HIGH_ENTROPY
                        ? Severity.HIGH
                        : Severity.MEDIUM;

                alert(ThreatType.DNS_TUNNELING,
                        key + ":TUNNEL",
                        now,
                        srcIP, srcMac, dstIP, dstMac,
                        "Suspicious DNS query: " + truncate(domain, 60)
                                + " (len=" + domain.length()
                                + ", entropy=" + String.format("%.2f", entropy) + ")",
                        sev, windowCount, winMs, ctx.getProtocol(), DNS_PORT);
            }
        }

        // DGA / MANY UNIQUE DOMAINS
        if (rec.getUniqueSubdomainCount() >= UNIQUE_SUB_THRESH) {

            alert(ThreatType.DNS_TUNNELING,
                    key + ":DGA",
                    now,
                    srcIP, srcMac, dstIP, dstMac,
                    "High number of unique DNS queries: "
                            + rec.getUniqueSubdomainCount(),
                    Severity.HIGH,
                    windowCount, winMs,
                    ctx.getProtocol(), DNS_PORT);
        }


        // DNS AMPLIFICATION (basic)
     // DNS AMPLIFICATION — heuristic: a response over the classic
     // 512-byte non-EDNS UDP ceiling usually means a large record type
     // (TXT/ANY/DNSSEC) was requested, which is the standard amplification
     // vector. This is a size heuristic, not full query/response
     // correlation by transaction ID — that's a reasonable next step if
     // this still shows false positives, but isn't needed to fix the
     // "fires on every reply" bug the old windowCount check had.
     if (ctx.getSrcPort() == DNS_PORT
             && ctx.isUdp()
             && ctx.getPayloadLength() > AMPLIFICATION_SIZE_THRESHOLD) {

         alert(ThreatType.DNS_AMPLIFICATION,
             key + ":AMP",
             now,
             srcIP, srcMac, dstIP, dstMac,
             "Large DNS response (" + ctx.getPayloadLength()
                 + " bytes) from " + srcIP + " — possible amplification source",
             Severity.MEDIUM,
             1, 0,
             ctx.getProtocol(), DNS_PORT);
     }
    }

    
	// HELPERS
    //You should later populate domain inside PacketContext
    private String extractDomain(byte[] payload) {
        if (payload == null || payload.length < 13) return null;

        try {
            int qdCount = ((payload[4] & 0xFF) << 8) | (payload[5] & 0xFF);
            if (qdCount < 1) return null;

            StringBuilder domain = new StringBuilder();
            int pos = 12;

            while (pos < payload.length) {
                int labelLen = payload[pos] & 0xFF;

                if (labelLen == 0) break; // root label, end of QNAME

                // Compression pointers (top two bits set) can't legally start
                // a first question's QNAME, but malformed/crafted packets
                // could include one. Bail out safely rather than misreading.
                if ((labelLen & 0xC0) == 0xC0) break;

                pos++;
                if (pos + labelLen > payload.length) return null; // truncated

                if (domain.length() > 0) domain.append('.');
                domain.append(new String(payload, pos, labelLen,
                        java.nio.charset.StandardCharsets.US_ASCII));
                pos += labelLen;
            }

            return domain.length() > 0 ? domain.toString() : null;

        } catch (Exception e) {
            return null; // never let a malformed packet crash the detector
        }
    }
    private double shannonEntropy(String s) {
        if (s == null || s.isEmpty()) return 0;

        Map<Character, Integer> freq = new java.util.HashMap<>();
        for (char c : s.toCharArray()) {
            freq.merge(c, 1, Integer::sum);
        }

        double entropy = 0;
        double len = s.length();

        for (int count : freq.values()) {
            double p = count / len;
            entropy -= p * (Math.log(p) / Math.log(2));
        }

        return entropy;
    }

    private String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }

    private void alert(ThreatType type, String alertKey, long now,
                       String srcIP, String srcMac, String dstIP, String dstMac,
                       String details, Severity severity,
                       int count, long winMs, String proto, int port) {

        Long last = lastAlerts.get(alertKey);
        if (last != null && (now - last) < COOLDOWN_MS) return;

        lastAlerts.put(alertKey, now);

        alertManager.raise(new ThreatEvent(
                type, srcIP, srcMac, dstIP, dstMac,
                count, winMs, details, severity,
                proto, "DNS_QUERY", port
        ));
    }
    private String firstLabel(String domain) {
        int dot = domain.indexOf('.');
        return dot > 0 ? domain.substring(0, dot) : domain;
    }

    public void cleanup() {
        long now = System.currentTimeMillis();

        records.entrySet().removeIf(e ->
                (now - e.getValue().getLastSeen()) > 600_000L);

        lastAlerts.entrySet().removeIf(e ->
                (now - e.getValue()) > 60_000L);
    }
}