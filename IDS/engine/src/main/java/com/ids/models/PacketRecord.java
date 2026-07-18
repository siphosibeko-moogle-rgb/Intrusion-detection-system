package com.ids.models;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-source (or per-flow) traffic accumulator shared by the detectors.
 *
 * REWRITE (bucket-counter model): rate-style metrics used to be ArrayLists
 * of raw event timestamps, pruned with removeIf() on every add AND every
 * read. Under flood traffic — exactly when detectors fire hardest — each
 * packet paid an O(window-population) scan plus per-event allocation, and a
 * 100k-pps burst held ~200k boxed Longs per list. Every windowed count is
 * now a fixed ring of {@value BucketRing#BUCKETS} bucket counters: O(1) per
 * event, zero allocation after construction, memory constant regardless of
 * packet rate.
 *
 * Window semantics: a count covers the last window±one bucket (window/16),
 * because expiry happens a whole bucket at a time instead of per event.
 * Threshold checks tolerate that ±6% edge; nothing reads exact event times.
 *
 * UNIQUE-VALUE metrics (scanned ports, DNS subdomains) keep their
 * last-seen maps: distinct-count semantics can't be expressed as a counter,
 * and their size is bounded by value cardinality, not packet rate.
 *
 * THREADING: unchanged — every mutator/reader is synchronized on this
 * record, matching the old model (concurrent capture threads share records).
 */
public class PacketRecord {

    private final String sourceIP;
    private volatile String sourceMac;
    private final long startTime;
    private volatile long lastSeen;

    private static final long WINDOW_2S = 2000L;
    private static final long WINDOW_60S = 60000L;

    /**
     * Ring of bucket counters approximating a sliding-window sum.
     * Each slot covers bucketMs; a slot is lazily reset when its absolute
     * bucket index (epoch) is superseded. Guarded by the enclosing
     * PacketRecord monitor — no internal synchronization.
     */
    private static final class BucketRing {
        private static final int BUCKETS = 16;

        private final long bucketMs;
        private final long[] epochs = new long[BUCKETS];
        private final long[] counts = new long[BUCKETS];

        BucketRing(long windowMs) {
            this.bucketMs = Math.max(1, windowMs / BUCKETS);
            java.util.Arrays.fill(epochs, -1);
        }

        void add(long now, long amount) {
            long epoch = now / bucketMs;
            int slot = (int) (epoch % BUCKETS);
            if (epochs[slot] != epoch) {
                epochs[slot] = epoch;
                counts[slot] = 0;
            }
            counts[slot] += amount;
        }

        long sum(long now) {
            long nowEpoch = now / bucketMs;
            long oldest = nowEpoch - BUCKETS + 1;
            long total = 0;
            for (int i = 0; i < BUCKETS; i++) {
                if (epochs[i] >= oldest && epochs[i] <= nowEpoch) total += counts[i];
            }
            return total;
        }

        /**
         * Age of the oldest in-window activity, measured from that bucket's
         * start (over-estimates the old first-timestamp version by at most
         * one bucketMs). 0 when the window is empty.
         */
        long windowDurationMs(long now) {
            long nowEpoch = now / bucketMs;
            long oldest = nowEpoch - BUCKETS + 1;
            long oldestActive = Long.MAX_VALUE;
            for (int i = 0; i < BUCKETS; i++) {
                if (counts[i] > 0 && epochs[i] >= oldest && epochs[i] <= nowEpoch) {
                    oldestActive = Math.min(oldestActive, epochs[i]);
                }
            }
            if (oldestActive == Long.MAX_VALUE) return 0;
            return Math.max(0, now - oldestActive * bucketMs);
        }
    }

    // CORE TRACKING
    private int totalPackets = 0;
    private long totalInboundBytes = 0;
    private long totalOutboundBytes = 0;

    // RATE WINDOWS (bucket rings — see class doc)
    private final BucketRing packets      = new BucketRing(WINDOW_2S);
    private final BucketRing synEvents    = new BucketRing(WINDOW_2S);
    private final BucketRing finEvents    = new BucketRing(WINDOW_2S);
    private final BucketRing nullEvents   = new BucketRing(WINDOW_2S);
    private final BucketRing xmasEvents   = new BucketRing(WINDOW_2S);
    private final BucketRing udpEvents    = new BucketRing(WINDOW_2S);
    private final BucketRing establishedEvents = new BucketRing(WINDOW_2S);
    private final BucketRing dnsQueries   = new BucketRing(WINDOW_2S);
    private final BucketRing afterHours   = new BucketRing(WINDOW_60S);
    private final BucketRing inboundWindow  = new BucketRing(WINDOW_60S);
    private final BucketRing outboundWindow = new BucketRing(WINDOW_60S);

    // UNIQUE-VALUE WINDOWS (last-seen maps — distinct counts, not rates)
    private final Map<String, Long> dnsSubdomains = new ConcurrentHashMap<>();
    private final Map<Integer, Long> scannedPorts = new ConcurrentHashMap<>();

    public PacketRecord(String sourceIP, String sourceMac) {
        this.sourceIP = sourceIP;
        this.sourceMac = sourceMac;
        this.startTime = System.currentTimeMillis();
        this.lastSeen = this.startTime;
    }

    private void cleanPorts(long now) {
        scannedPorts.entrySet().removeIf(e -> (now - e.getValue()) > WINDOW_2S);
    }

    // PACKET TRACKING
    public synchronized void addTimestamp(long now) {
        totalPackets++;
        packets.add(now, 1);
        lastSeen = now;
    }

    public synchronized int getWindowCount(long now) {
        return (int) packets.sum(now);
    }

    // BYTE TRACKING
    public synchronized void addBytes(int bytes, boolean inbound, long now) {
        if (bytes <= 0) return;

        totalPackets++;
        lastSeen = now;

        if (inbound) {
            totalInboundBytes += bytes;
            inboundWindow.add(now, bytes);
        } else {
            totalOutboundBytes += bytes;
            outboundWindow.add(now, bytes);
        }
    }

    public synchronized long getWindowInboundBytes(long now) {
        return inboundWindow.sum(now);
    }

    public synchronized long getWindowOutboundBytes(long now) {
        return outboundWindow.sum(now);
    }

    // synchronized: these fields are written under the monitor in
    // addTimestamp()/addBytes(); unsynchronized reads could see stale/torn values.
    public synchronized int getTotalPacketCount() {
        return totalPackets;
    }

    public synchronized long getTotalSessionBytes() {
        return totalInboundBytes + totalOutboundBytes;
    }

    // SESSION INFO
    public String getSourceIP() { return sourceIP; }
    public String getSourceMac() { return sourceMac; }
    public long getLastSeen() { return lastSeen; }
    public long getSessionDurationMs() { return lastSeen - startTime; }

    // DNS
    public synchronized void addDnsSubdomain(String domain) {
        if (domain == null || domain.isEmpty()) return;

        long now = System.currentTimeMillis();
        dnsSubdomains.put(domain, now);
        dnsSubdomains.entrySet().removeIf(e -> (now - e.getValue()) > WINDOW_60S);
        lastSeen = now;
    }

    public synchronized void incrementDnsQuery() {
        long now = System.currentTimeMillis();
        dnsQueries.add(now, 1);
        lastSeen = now;
    }

    public synchronized int getUniqueSubdomainCount() {
        long now = System.currentTimeMillis();
        dnsSubdomains.entrySet().removeIf(e -> (now - e.getValue()) > WINDOW_60S);
        return dnsSubdomains.size();
    }

    // SYN
    public synchronized void recordSyn(long now) {
        synEvents.add(now, 1);
        lastSeen = now;
    }

    public synchronized int getSynCount(long now) {
        return (int) synEvents.sum(now);
    }

    // NULL
    public synchronized void recordNull(long now) {
        nullEvents.add(now, 1);
        lastSeen = now;
    }

    public synchronized int getNullCount(long now) {
        return (int) nullEvents.sum(now);
    }

    // FIN
    public synchronized void recordFin(long now) {
        finEvents.add(now, 1);
        lastSeen = now;
    }

    public synchronized int getFinCount(long now) {
        return (int) finEvents.sum(now);
    }

    // XMAS
    public synchronized void recordXmas(long now) {
        xmasEvents.add(now, 1);
        lastSeen = now;
    }

    public synchronized int getXmasCount(long now) {
        return (int) xmasEvents.sum(now);
    }

    // ESTABLISHED TRAFFIC
    // ACK-bearing, non-SYN packets: the source completed the handshake and is
    // exchanging real data on this flow. A half-open scanner (nmap -sS) never
    // produces these — it sends SYN, receives SYN/ACK, replies RST. Used by
    // NmapScanDetector to discount SYNs that were followed by actual
    // application traffic (browsing) from the SYN-scan count.
    public synchronized void recordEstablished(long now) {
        establishedEvents.add(now, 1);
        lastSeen = now;
    }

    public synchronized int getEstablishedCount(long now) {
        return (int) establishedEvents.sum(now);
    }

    // UDP
    public synchronized void recordUdp(long now) {
        udpEvents.add(now, 1);
        lastSeen = now;
    }

    public synchronized int getUdpCount(long now) {
        return (int) udpEvents.sum(now);
    }

    // PORT TRACKING
    public synchronized void addScannedPort(int port, long now) {
        if (port <= 0) return;

        scannedPorts.put(port, now);
        cleanPorts(now);
        lastSeen = now;
    }

    public synchronized int getUniquePortCount(long now) {
        cleanPorts(now);
        return scannedPorts.size();
    }

    public synchronized long getWindowDurationMs(long now) {
        return packets.windowDurationMs(now);
    }

    public synchronized void addAfterHoursTimestamp(long now) {
        afterHours.add(now, 1);
        lastSeen = now;
    }

    public synchronized int getAfterHoursWindowCount(long now) {
        return (int) afterHours.sum(now);
    }

    public void updateMacIfBlank(String mac) {
        if ((sourceMac == null || sourceMac.isEmpty())
                && mac != null && !mac.isEmpty()) {
            sourceMac = mac;
        }
    }
}
