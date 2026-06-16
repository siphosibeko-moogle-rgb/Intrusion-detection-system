package com.ids.entity;

import com.ids.enums.Severity;
import com.ids.enums.ThreatType;
import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "threat_events")
public class ThreatEventEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String sourceIp;
    private String destinationIp;

    @Enumerated(EnumType.STRING)
    private ThreatType threatType;

    @Enumerated(EnumType.STRING)
    private Severity severity;

    private String protocol;
    private Integer packetCount;

    private LocalDateTime timestamp;

    @Column(columnDefinition = "TEXT")
    private String details;

    // ✅ GETTERS + SETTERS (REQUIRED)

    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }

    public String getDestinationIp() { return destinationIp; }
    public void setDestinationIp(String destinationIp) { this.destinationIp = destinationIp; }

    public ThreatType getThreatType() { return threatType; }
    public void setThreatType(ThreatType threatType) { this.threatType = threatType; }

    public Severity getSeverity() { return severity; }
    public void setSeverity(Severity severity) { this.severity = severity; }

    public String getProtocol() { return protocol; }
    public void setProtocol(String protocol) { this.protocol = protocol; }

    public Integer getPacketCount() { return packetCount; }
    public void setPacketCount(Integer packetCount) { this.packetCount = packetCount; }

    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }

    public String getDetails() { return details; }
    public void setDetails(String details) { this.details = details; }
}