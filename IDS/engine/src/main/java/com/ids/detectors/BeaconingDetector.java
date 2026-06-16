package com.ids.detectors;

import com.ids.alerts.AlertManager;
import com.ids.models.PacketContext;
import com.ids.models.ThreatEvent;
import com.ids.models.ThreatEvent.Severity;
import com.ids.models.ThreatEvent.ThreatType;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Detects beaconing — malware phoning home at regular clock-like intervals.
 *
 * Logic:
 *   Track outbound connection timestamps per (srcIP → dstIP:port).
 *   Once we have MIN_SAMPLES hits, compute jitter (stddev / mean) of the
 *   inter-arrival gaps. Low jitter = suspiciously automated = beacon.
 */
public class BeaconingDetector implements Detector {

    private static final int    MIN_SAMPLES   = 5;
    private static final long   MAX_GAP_MS    = 600_000L;  // ignore gaps > 10 min
    private static final long   MIN_GAP_MS    = 5_000L;    // ignore gaps < 5 s
    private static final double JITTER_THRESH = 0.10;      // stddev/mean <= 10% → alert
    private static final long   COOLDOWN_MS   = 60_000L;

    // key = "srcIP->dstIP:port"
    private final Map<String, Deque<Long>> flowHistory = new ConcurrentHashMap<>();
    private final Map<String, Long>        lastAlerts  = new ConcurrentHashMap<>();

    private final AlertManager alertManager;

    public BeaconingDetector(AlertManager alertManager) {
        this.alertManager = alertManager;
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
        if (port <= 0 || port > 49151) return;

        String flowKey = srcIP + "->" + dstIP + ":" + port;

        Deque<Long> times = flowHistory.computeIfAbsent(flowKey, k -> new ArrayDeque<>());

        synchronized (times) {

            while (!times.isEmpty() && (now - times.peekFirst()) > MAX_GAP_MS * (MIN_SAMPLES + 1)) {
                times.pollFirst();
            }

            times.addLast(now);

            if (times.size() < MIN_SAMPLES + 1) return;

            Long[]   arr  = times.toArray(new Long[0]);
            double[] gaps = new double[arr.length - 1];
            for (int i = 0; i < gaps.length; i++) gaps[i] = arr[i + 1] - arr[i];

            for (double g : gaps) if (g < MIN_GAP_MS || g > MAX_GAP_MS) return;

            double mean   = mean(gaps);
            double stddev = stddev(gaps, mean);
            double jitter = stddev / mean;

            if (jitter <= JITTER_THRESH) {

                Long last = lastAlerts.get(flowKey);
                if (last != null && (now - last) < COOLDOWN_MS) return;

                lastAlerts.put(flowKey, now);

                alertManager.raise(new ThreatEvent(
                        ThreatType.BEACONING,
                        srcIP, srcMac, dstIP, dstMac,
                        times.size(),
                        MAX_GAP_MS,
                        String.format("Beacon: %s → %s:%d  interval=%.1fs  jitter=%.1f%%",
                                srcIP, dstIP, port, mean / 1000.0, jitter * 100.0),
                        Severity.HIGH,
                        ctx.isTcp() ? "TCP" : "UDP",
                        "BEACON",
                        port
                ));

                times.clear();
            }
        }
    }

    private double mean(double[] v) {
        double s = 0; for (double x : v) s += x; return s / v.length;
    }

    private double stddev(double[] v, double mean) {
        double s = 0; for (double x : v) s += (x - mean) * (x - mean); return Math.sqrt(s / v.length);
    }

    public void cleanup() {
        long now = System.currentTimeMillis();
        flowHistory.entrySet().removeIf(e -> {
            synchronized (e.getValue()) {
                return e.getValue().isEmpty() ||
                       (now - e.getValue().peekLast()) > MAX_GAP_MS * 2;
            }
        });
        lastAlerts.entrySet().removeIf(e -> (now - e.getValue()) > COOLDOWN_MS * 2);
    }
}