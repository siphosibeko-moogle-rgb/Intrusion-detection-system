package com.ids.models;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

public class ThreatEvent {

    public enum ThreatType {
        ICMP_FLOOD, ICMP_PING_SWEEP,
        NMAP_SYN_SCAN, NMAP_NULL_SCAN, NMAP_FIN_SCAN,
        NMAP_XMAS_SCAN, NMAP_UDP_SCAN, NMAP_PORT_SWEEP, NMAP_OS_DETECTION,
        UNKNOWN_IP, UNKNOWN_MAC, OUTSIDE_SUBNET,
        ARP_SPOOFING, ARP_POISONING, ARP_FLOOD, GRATUITOUS_ARP,
        DNS_TUNNELING, DNS_FLOOD, DNS_AMPLIFICATION,
        BULK_DOWNLOAD, DATA_EXFILTRATION, SUSTAINED_LARGE_TRANSFER,
        AFTER_HOURS_ACCESS, WEEKEND_ACCESS, AFTER_HOURS_SERVER_ACCESS,
        BRUTE_FORCE_ATTEMPT, BRUTE_FORCE_SUCCESS, PORT_KNOCKING, BEACONING, 
        LATERAL_MOVEMENT, HTTP_FLOOD, HTTP_OVERSIZED_URI, HTTP_SUSPICIOUS_VERB, 
        HTTP_SCANNER_AGENT, ROGUE_DHCP,
        FTP_SESSION,
        FTP_DATA_TRANSFER,
        FTP_CLEARTEXT_CREDENTIALS,
        SMB_EXTERNAL,
        SCP_SFTP_TRANSFER,
        DATA_STAGING,
        DATA_STAGING_MULTI_PORT, UBA_NEW_SERVICE_PORT, 
        UBA_BURST_ACTIVITY, UBA_NEW_DESTINATION, UBA_NEW_PROTOCOL, LOW_AND_SLOW_SCAN,
        SQL_INJECTION, SYN_FLOOD
    }

    public enum Severity {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    private final ThreatType type;

    @JsonProperty("sourceIp")
    private final String sourceIP;

    @JsonProperty("sourceMac")
    private final String sourceMac;

    @JsonProperty("destinationIp")
    private final String destinationIP;

    @JsonProperty("destinationMac")
    private final String destinationMac;

    private final int packetCount;
    private final long windowMillis;

    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private final LocalDateTime timestamp;

    private final String details;
    private final Severity severity;
    private final String protocol;
    private final String requestType;
    private final int destinationPort;

    private String hostName = "ids-sensor";

    public ThreatEvent(
            ThreatType type,
            String sourceIP,
            String sourceMac,
            String destinationIP,
            String destinationMac,
            int packetCount,
            long windowMillis,
            String details,
            Severity severity,
            String protocol,
            String requestType,
            int destinationPort
    ) {
        this.type = type;
        this.sourceIP = sourceIP;
        this.sourceMac = sourceMac;
        this.destinationIP = destinationIP;
        this.destinationMac = destinationMac;
        this.packetCount = packetCount;
        this.windowMillis = windowMillis;
        this.timestamp = LocalDateTime.now();
        this.details = details;
        this.severity = severity;
        this.protocol = protocol;
        this.requestType = requestType;
        this.destinationPort = destinationPort;
    }

    //Convert to API-compatible structure
    public Map<String, Object> toMap() {
        Map<String, Object> map = new HashMap<>();

        map.put("threatType",    type.name());
        map.put("severity",      severity.name());
        map.put("sourceIp",      sourceIP);
        map.put("sourceMac",     sourceMac     != null ? sourceMac     : "");  // ← TOP LEVEL
        map.put("destIp",        destinationIP != null ? destinationIP : "");  // ← "destIp" not "destinationIp"
        map.put("destMac",       destinationMac != null ? destinationMac : "");
        map.put("protocol",      protocol);
        map.put("requestType",   requestType);
        map.put("packetCount",   packetCount);
        map.put("windowMs",      windowMillis);
        map.put("timestamp",     timestamp.toString());
        map.put("details",       details       != null ? details       : "");
        map.put("destinationPort", destinationPort);

        return map;
    }

    // getters (unchanged)
    public ThreatType getType(){ 
    	return type; }
    
    public String getSourceIP(){ 
    	return sourceIP; }
    
    public String getSourceMac(){ 
    	return sourceMac; }
    
    public String getDestinationIP(){ 
    	return destinationIP; }
    
    public String getDestinationMac(){ 
    	return destinationMac; }
    
    public int getPacketCount(){ 
    	return packetCount; }
    
    public long getWindowMillis(){ 
    	return windowMillis; }
    
    public LocalDateTime getTimestamp() { 
    	return timestamp; }
    
    public String getDetails() { 
    	return details; }
    
    public Severity getSeverity(){ 
    	return severity; }
    public String getProtocol(){ 
    	return protocol; }
    
    public String getRequestType(){ 
    	return requestType; }
    
    public int getDestinationPort(){
    	return destinationPort; }
    
    public String getHostName(){ 
    	return hostName; }
    
    public void setHostName(String h){ 
    	this.hostName = h; }
    
    @Override
    public String toString() {
        return String.format("[%s] %s | src=%s (%s) -> dst=%s | severity=%s | %s",
            timestamp, type.name(), sourceIP, sourceMac, destinationIP, severity, details);
    }
}