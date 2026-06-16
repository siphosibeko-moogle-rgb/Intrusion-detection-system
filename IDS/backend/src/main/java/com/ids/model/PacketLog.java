package com.ids.model;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * Raw packet metadata stored for forensic analysis.
 * Every packet that triggered an alert is logged here.
 * Can be linked to a ForensicCase via caseId.
 */
@Entity
@Table(name = "packet_logs",
       indexes = {
           @Index(name = "idx_pkt_src_ip",  columnList = "sourceIp"),
           @Index(name = "idx_pkt_src_mac", columnList = "sourceMac"),
           @Index(name = "idx_pkt_ts",      columnList = "capturedAt"),
           @Index(name = "idx_pkt_case",    columnList = "caseId")
       })
public class PacketLog {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String  sourceIp;
    private String  sourceMac;
    private String  destIp;
    private String  destMac;
    private String  protocol;
    private String  requestType;
    private Integer srcPort;
    private Integer dstPort;
    private Integer tcpFlags;
    private Integer ttl;
    private Integer packetLength;
    private Integer windowSize;
    private String  threatType;
    private String  severity;
    private String  detectorName;

    @Column(length = 1000)
    private String details;

    private Instant capturedAt;
    private Long    caseId;

    @PrePersist
    public void prePersist() { 
    	if (capturedAt == null) capturedAt = Instant.now();
    	}

    public Long getId() { 
    	return id; 
    	}
    public String getSourceIp(){ 
    	return sourceIp; 
    	}
    public String getSourceMac() { 
    	return sourceMac; 
    	}
    public String getDestIp(){ 
    	return destIp; 
    	}
    public String getDestMac(){ 
    	return destMac; 
    	}
    public String getProtocol(){ 
    	return protocol; }
    public String  getRequestType(){ 
    	return requestType; }
    public Integer getSrcPort() { 
    	return srcPort; 
    	}
    public Integer getDstPort(){ 
    	return dstPort; 
    	}
    public Integer getTcpFlags() { 
    	return tcpFlags; 
    	}
    public Integer getTtl() { 
    	return ttl; }
    public Integer getPacketLength() { 
    	return packetLength; 
    	}
    public Integer getWindowSize() { 
    	return windowSize;
    	}
    public String getThreatType() { 
    	return threatType; 
    	}
    public String getSeverity()  { 
    	return severity; 
    	}
    public String getDetectorName() { 
    	return detectorName; 
    	}
    public String getDetails() { 
    	return details; 
    	}
    public Instant getCapturedAt() { 
    	return capturedAt; 
    	}
    public Long getCaseId()  { 
    	return caseId; 
    	}

    public void setSourceIp(String v)     { 
    	sourceIp     = v; 
    	}
    public void setSourceMac(String v)    { 
    	sourceMac    = v; 
    	}
    public void setDestIp(String v)       { 
    	destIp       = v; }
    public void setDestMac(String v)      { destMac      = v; }
    public void setProtocol(String v)     { protocol     = v; }
    public void setRequestType(String v)  { requestType  = v; }
    public void setSrcPort(Integer v)     { srcPort      = v; }
    public void setDstPort(Integer v)     { dstPort      = v; }
    public void setTcpFlags(Integer v)    { tcpFlags     = v; }
    public void setTtl(Integer v)         { ttl          = v; }
    public void setPacketLength(Integer v){ packetLength  = v; }
    public void setWindowSize(Integer v)  { windowSize   = v; }
    public void setThreatType(String v)   { threatType   = v; }
    public void setSeverity(String v)     { severity     = v; }
    public void setDetectorName(String v) { detectorName = v; }
    public void setDetails(String v)      { details      = v; }
    public void setCapturedAt(Instant v)  { capturedAt   = v; }
    public void setCaseId(Long v)         { caseId       = v; }
}