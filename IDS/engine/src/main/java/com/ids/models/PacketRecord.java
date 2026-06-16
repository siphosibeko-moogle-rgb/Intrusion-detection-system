package com.ids.models;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class PacketRecord {

    private final String sourceIP;
    private volatile String sourceMac;
    private final long startTime;
    private volatile long lastSeen;

    private static final long WINDOW_2S = 2000L;
    private static final long WINDOW_60S = 60000L;

    //CORE TRACKING
    private int totalPackets = 0;
    private long totalInboundBytes = 0;
    private long totalOutboundBytes = 0;

    //TIME-BASED EVENTS
    private final List<Long> timestamps = new ArrayList<>();
    private final List<Long> synEvents = new ArrayList<>();
    private final List<Long> finEvents = new ArrayList<>();
    private final List<Long> nullEvents = new ArrayList<>();
    private final List<Long> xmasEvents = new ArrayList<>();
    private final List<Long> udpEvents = new ArrayList<>();
    private final List<Long> osProbeEvents = new ArrayList<>();

    //DNS
    private final List<Long> dnsQueryTimestamps = new ArrayList<>();
    private final Map<String, Long> dnsSubdomains = new ConcurrentHashMap<>();

    //PORT SCAN
    private final Map<Integer, Long> scannedPorts = new ConcurrentHashMap<>();

    //BYTE WINDOW
    private final List<long[]> byteWindow = new ArrayList<>();

    //AFTER HOURS
    private final List<Long> afterHoursTs = new ArrayList<>();

    public PacketRecord(String sourceIP, String sourceMac) {
        this.sourceIP = sourceIP;
        this.sourceMac = sourceMac;
        this.startTime = System.currentTimeMillis();
        this.lastSeen = this.startTime;
    }
    // CLEANERS
    private void clean(List<Long> list, long now, long window) {
        list.removeIf(t -> (now - t) > window);
    }

    private void cleanPorts(long now) {
        scannedPorts.entrySet().removeIf(e -> (now - e.getValue()) > WINDOW_2S);
    }

    // PACKET TRACKING
    public synchronized void addTimestamp(long now) {
        totalPackets++;
        timestamps.add(now);
        clean(timestamps, now, WINDOW_2S);
        lastSeen = now;
    }

    public synchronized int getWindowCount(long now) {
        clean(timestamps, now, WINDOW_2S);
        return timestamps.size();
    }

    // BYTE TRACKING
    public synchronized void addBytes(int bytes, boolean inbound, long now) {
        if (bytes <= 0) return;

        totalPackets++;
        lastSeen = now;

        if (inbound) totalInboundBytes += bytes;
        else totalOutboundBytes += bytes;

        byteWindow.add(new long[]{now, inbound ? bytes : 0, inbound ? 0 : bytes});
        byteWindow.removeIf(e -> (now - e[0]) > WINDOW_60S);
    }

    public synchronized long getWindowInboundBytes(long now) {
        byteWindow.removeIf(e -> (now - e[0]) > WINDOW_60S);
        return byteWindow.stream().mapToLong(e -> e[1]).sum();
    }

    public synchronized long getWindowOutboundBytes(long now) {
        byteWindow.removeIf(e -> (now - e[0]) > WINDOW_60S);
        return byteWindow.stream().mapToLong(e -> e[2]).sum();
    }
    
    
    public int getTotalPacketCount() {
        return totalPackets;
    }

    public long getTotalSessionBytes() {
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
        dnsQueryTimestamps.add(now);
        clean(dnsQueryTimestamps, now, WINDOW_2S);
        lastSeen = now;
    }

    public synchronized int getUniqueSubdomainCount() {
        long now = System.currentTimeMillis();
        dnsSubdomains.entrySet().removeIf(e -> (now - e.getValue()) > WINDOW_60S);
        return dnsSubdomains.size();
    }

 // SYN
 public synchronized void recordSyn(long now) {
     synEvents.add(now);
     clean(synEvents, now, WINDOW_2S);
     lastSeen = now;
 }

 public synchronized int getSynCount(long now) {
     clean(synEvents, now, WINDOW_2S);
     return synEvents.size();
 }

 // NULL
 public synchronized void recordNull(long now) {
     nullEvents.add(now);
     clean(nullEvents, now, WINDOW_2S);
     lastSeen = now;
 }

 public synchronized int getNullCount(long now) {
     clean(nullEvents, now, WINDOW_2S);
     return nullEvents.size();
 }

 // FIN
 public synchronized void recordFin(long now) {
     finEvents.add(now);
     clean(finEvents, now, WINDOW_2S);
     lastSeen = now;
 }

 public synchronized int getFinCount(long now) {
     clean(finEvents, now, WINDOW_2S);
     return finEvents.size();
 }

 
 // XMAS
 public synchronized void recordXmas(long now) {
     xmasEvents.add(now);
     clean(xmasEvents, now, WINDOW_2S);
     lastSeen = now;
 }

 public synchronized int getXmasCount(long now) {
     clean(xmasEvents, now, WINDOW_2S);
     return xmasEvents.size();
 }
 // UDP

 public synchronized void recordUdp(long now) {
     udpEvents.add(now);
     clean(udpEvents, now, WINDOW_2S);
     lastSeen = now;
 }

 public synchronized int getUdpCount(long now) {
     clean(udpEvents, now, WINDOW_2S);
     return udpEvents.size();
 }
 
 //PORT TRACKING

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

public long getWindowDurationMs(long now) {
    clean(timestamps, now, WINDOW_2S);
    if (timestamps.isEmpty()) return 0;
    return now - timestamps.get(0);
}

public synchronized void addAfterHoursTimestamp(long now) {
    afterHoursTs.add(now);
    afterHoursTs.removeIf(t -> (now - t) > 60000L);
    lastSeen = now;
}
public synchronized int getAfterHoursWindowCount(long now) {
    afterHoursTs.removeIf(t -> (now - t) > 60000L);
    return afterHoursTs.size();
}
public void updateMacIfBlank(String mac) {
    if ((sourceMac == null || sourceMac.isEmpty()) 
            && mac != null && !mac.isEmpty()) {
        sourceMac = mac;
    }
}
}