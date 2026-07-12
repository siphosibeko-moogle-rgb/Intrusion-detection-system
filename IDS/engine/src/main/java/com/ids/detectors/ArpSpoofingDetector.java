package com.ids.detectors;

import com.ids.alerts.AlertSink;
import com.ids.models.ThreatEvent;
import com.ids.models.ThreatEvent.Severity;
import com.ids.models.ThreatEvent.ThreatType;

import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.ArpOperation;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Detects ARP Spoofing, ARP Poisoning, ARP Flood, and Gratuitous ARP.
 */
public class ArpSpoofingDetector implements Detector {

    private final Map<String, String>    ipToMacTable    = new ConcurrentHashMap<>();
    private final Map<String, Long>      conflictLog     = new ConcurrentHashMap<>();
    private final Map<String, List<Long>>arpRateTracker  = new ConcurrentHashMap<>();
    private final Map<String, Set<String>>pendingRequests= new ConcurrentHashMap<>();

    private static final int  FLOOD_THRESHOLD   = 30;
    private static final long WINDOW_MS         = 2_000L;
    private static final long CONFLICT_COOLDOWN = 5_000L;

    private final AlertSink alertManager;
    private final String       gatewayIp;

    public ArpSpoofingDetector(AlertSink alertManager, String gatewayIp) {
        this.alertManager = alertManager;
        this.gatewayIp    = gatewayIp;
    }

    public void analyze(Packet packet) {
        if (!(packet instanceof EthernetPacket eth)) 
        	return;
        if (!(eth.getPayload() instanceof ArpPacket arp)) 
        	return;

        ArpPacket.ArpHeader hdr   = arp.getHeader();
        ArpOperation        op    = hdr.getOperation();
        String senderIP  = hdr.getSrcProtocolAddr().getHostAddress();
        String senderMac = hdr.getSrcHardwareAddr().toString();
        String targetIP  = hdr.getDstProtocolAddr().getHostAddress();
        String targetMac = hdr.getDstHardwareAddr().toString();
        long   now       = System.currentTimeMillis();

        if (op.equals(ArpOperation.REQUEST)) {
            pendingRequests.computeIfAbsent(targetIP, k -> ConcurrentHashMap.newKeySet()).add(senderMac);
            learn(senderIP, senderMac);
            return;
        }
        if (!op.equals(ArpOperation.REPLY)) return;

        // ARP flood
        List<Long> times = arpRateTracker.computeIfAbsent(senderMac,
            k -> Collections.synchronizedList(new ArrayList<>()));
        times.add(now);
        times.removeIf(t -> (now - t) > WINDOW_MS);
        if (times.size() >= FLOOD_THRESHOLD)
            alertManager.raise(new ThreatEvent(ThreatType.ARP_FLOOD,
					                senderIP, 
					                senderMac, 
					                targetIP, 
					                targetMac, 
					                times.size(),
					                WINDOW_MS,
                "ARP reply flood: "+times.size()+" replies/2s from "+senderIP+" ["+senderMac+"]",
                Severity.HIGH, "ARP", "REPLY", 0));

        // Gratuitous ARP
        Set<String> requesters = pendingRequests.get(senderIP);
        if (requesters == null || requesters.isEmpty()) {
            // Non-gateway unsolicited ARP is routine (DHCP renewal, Wi-Fi
            // reconnect, VRRP) → LOW. A host claiming to be the GATEWAY
            // unprompted is the textbook first packet of an ARP MITM → CRITICAL.
            Severity sev = senderIP.equals(gatewayIp) ? Severity.CRITICAL : Severity.LOW;
            alertManager.raise(new ThreatEvent(ThreatType.GRATUITOUS_ARP,
					                senderIP, 
					                senderMac, 
					                targetIP, 
					                targetMac, 
					                1, 0,
                "Unsolicited ARP reply from "+senderIP+" ["+senderMac+"]"
                + (senderIP.equals(gatewayIp) ? " — GATEWAY!" : ""),
                sev, "ARP", "GRATUITOUS_REPLY", 0));
        }

        // ARP Spoofing
        String knownMac = ipToMacTable.get(senderIP);
        if (knownMac != null && !knownMac.equalsIgnoreCase(senderMac)) {
            String conflictKey = senderIP + ":" + senderMac;
            Long   lastAlert   = conflictLog.get(conflictKey);
            if (lastAlert == null || (now - lastAlert) > CONFLICT_COOLDOWN) {
                conflictLog.put(conflictKey, now);
                boolean gatewaySpoof = senderIP.equals(gatewayIp);
                Severity sev = gatewaySpoof ? Severity.CRITICAL : Severity.HIGH;
                alertManager.raise(new ThreatEvent(ThreatType.ARP_SPOOFING,
							                    senderIP, 
							                    senderMac, 
							                    targetIP, 
							                    targetMac, 
							                    1, 0,
                    "ARP SPOOFING: IP "+senderIP+" was "+knownMac+" now claims "+senderMac
                    +(gatewaySpoof ? " — GATEWAY SPOOFED! MITM ATTACK!" : ""),
                    sev, "ARP", "SPOOFED_REPLY", 0));
                if (gatewaySpoof)
                    alertManager.raise(new ThreatEvent(ThreatType.ARP_POISONING,
						                        senderIP, 
						                        senderMac, 
						                        gatewayIp, 
						                        targetMac, 
						                        1, 0,
                        "ARP CACHE POISONING: Gateway "+gatewayIp+" spoofed by "+senderMac
                        +" — ALL TRAFFIC MAY BE INTERCEPTED",
                        Severity.CRITICAL, "ARP", "CACHE_POISON", 0));
            }
        } else {
            learn(senderIP, senderMac);
        }
        if (requesters != null) requesters.remove(eth.getHeader().getSrcAddr().toString());
    }

    private void learn(String ip, String mac) {
        if (ip != null && mac != null && !ip.equals("0.0.0.0"))
            ipToMacTable.putIfAbsent(ip.toLowerCase(), mac.toLowerCase());
    }

    public void cleanup() {
        pendingRequests.entrySet().removeIf(e -> e.getValue().isEmpty());
        conflictLog.entrySet().removeIf(e -> (System.currentTimeMillis()-e.getValue()) > 30_000L);
    }
}