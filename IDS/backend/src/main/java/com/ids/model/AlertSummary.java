package com.ids.model;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "alert_summary",
       uniqueConstraints = {
           @UniqueConstraint(name = "uq_alert_summary_ip_type",
                              columnNames = {"source_ip", "threat_type"})
       },
       indexes = {
           @Index(name = "idx_summary_last_seen", columnList = "last_seen"),
           @Index(name = "idx_summary_severity",  columnList = "severity")
       })
public class AlertSummary {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "threat_type", nullable = false)
    private String threatType;

    @Column(name = "source_ip", nullable = false)
    private String sourceIp;

    @Column(name = "source_mac")
    private String sourceMac;

    @Column(name = "dest_ip")
    private String destIp;

    @Column(name = "dest_mac")
    private String destMac;

    @Column(name = "protocol")
    private String protocol;

    @Column(name = "request_type")
    private String requestType;

    @Column(name = "packet_count")
    private int packetCount;

    @Column(name = "window_ms")
    private long windowMs;

    @Column(name = "severity")
    private String severity;

    @Column(name = "details", length = 1000)
    private String details;

    @Column(name = "occurrence_count", nullable = false)
    private int occurrenceCount;

    @Column(name = "first_seen", nullable = false)
    private Instant firstSeen;

    @Column(name = "last_seen", nullable = false)
    private Instant lastSeen;

    public Long getId() { return id; }
    public String getThreatType() { return threatType; }
    public String getSourceIp() { return sourceIp; }
    public String getSourceMac() { return sourceMac; }
    public String getDestIp() { return destIp; }
    public String getDestMac() { return destMac; }
    public String getProtocol() { return protocol; }
    public String getRequestType() { return requestType; }
    public int getPacketCount() { return packetCount; }
    public long getWindowMs() { return windowMs; }
    public String getSeverity() { return severity; }
    public String getDetails() { return details; }
    public int getOccurrenceCount() { return occurrenceCount; }
    public Instant getFirstSeen() { return firstSeen; }
    public Instant getLastSeen() { return lastSeen; }

    public void setId(Long v) { id = v; }
    public void setThreatType(String v) { threatType = v; }
    public void setSourceIp(String v) { sourceIp = v; }
    public void setSourceMac(String v) { sourceMac = v; }
    public void setDestIp(String v) { destIp = v; }
    public void setDestMac(String v) { destMac = v; }
    public void setProtocol(String v) { protocol = v; }
    public void setRequestType(String v) { requestType = v; }
    public void setPacketCount(int v) { packetCount = v; }
    public void setWindowMs(long v) { windowMs = v; }
    public void setSeverity(String v) { severity = v; }
    public void setDetails(String v) { details = v; }
    public void setOccurrenceCount(int v) { occurrenceCount = v; }
    public void setFirstSeen(Instant v) { firstSeen = v; }
    public void setLastSeen(Instant v) { lastSeen = v; }
}