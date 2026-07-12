package com.ids.detectors;

import com.ids.alerts.AlertSink;
import com.ids.models.PacketContext;
import com.ids.models.PacketRecord;
import com.ids.models.ThreatEvent;
import com.ids.models.ThreatEvent.Severity;
import com.ids.models.ThreatEvent.ThreatType;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class IcmpAbuseDetector implements Detector {

    private static final int FLOOD_THRESHOLD = 20;
    private static final int SWEEP_THRESHOLD = 5;
    private static final long COOLDOWN_MS = 2000L;

    private final Map<String, PacketRecord> records = new ConcurrentHashMap<>();
    private final Map<String, Long> lastAlerts = new ConcurrentHashMap<>();

    private final AlertSink alertManager;

    public IcmpAbuseDetector(AlertSink alertManager) {
        this.alertManager = alertManager;
    }

    public void analyze(PacketContext ctx) {

        // Only ICMP echo requests
        if (!ctx.isIcmp() || !ctx.isIcmpEchoRequest()) 
        	return;

        String srcIP  = ctx.getSrcIp();
        String dstIP  = ctx.getDstIp();
        String srcMac = ctx.getSrcMac();
        String dstMac = ctx.getDstMac();

        if (srcIP == null) 
        	return;

        long now = System.currentTimeMillis();

        PacketRecord rec = records.computeIfAbsent(srcIP,
                k -> new PacketRecord(srcIP, srcMac));

        rec.addTimestamp(now);

        // Track sweep
        rec.addScannedPort(dstIP.hashCode(), now); // hack: reuse structure

        int packetCount = rec.getWindowCount(now);
        int uniqueHosts = rec.getUniquePortCount(now);

        // FLOOD
        alert(ThreatType.ICMP_FLOOD,
                srcIP + ":FLOOD",
                packetCount,
                FLOOD_THRESHOLD,
                srcIP, srcMac, dstIP, dstMac,
                now, rec,
                "ICMP flood from " + srcIP,
                Severity.HIGH);

        // SWEEP
        alert(ThreatType.ICMP_PING_SWEEP,
                srcIP + ":SWEEP",
                uniqueHosts,
                SWEEP_THRESHOLD,
                srcIP, srcMac, dstIP, dstMac,
                now, rec,
                "Ping sweep from " + srcIP,
                Severity.MEDIUM);
    }

    private void alert(ThreatType type,
                       String key,
                       int count,
                       int threshold,
                       String srcIP,
                       String srcMac,
                       String dstIP,
                       String dstMac,
                       long now,
                       PacketRecord rec,
                       String msg,
                       Severity sev) {

        if (count < threshold) return;

        Long last = lastAlerts.get(key);
        if (last != null && now - last < COOLDOWN_MS) return;

        lastAlerts.put(key, now);

        alertManager.raise(new ThreatEvent(
                type,
                srcIP,
                srcMac,
                dstIP,
                dstMac,
                rec.getWindowCount(now),
                2000,
                msg,
                sev,
                "ICMP",
                "ECHO_REQUEST",
                0
        ));
    }

    public void cleanup() {
        long now = System.currentTimeMillis();
        records.entrySet().removeIf(e ->
                now - e.getValue().getLastSeen() > 10000
        );
    }
}