package com.ids.model;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "alerts",
       indexes = {
           @Index(name = "idx_alert_source_ip",   
        		   	columnList = "sourceIp"),
           @Index(name = "idx_alert_severity",
           			columnList = "severity"),
           @Index(name = "idx_alert_timestamp",   
           			columnList = "timestamp"),
           @Index(name = "idx_alert_threat_type", 
           			columnList = "threatType")
       })
public class Alert {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String threatType;
    private String sourceIp;
    private String sourceMac;
    private String destIp;
    private String destMac;
    private String protocol;
    private String requestType;
    private int packetCount;
    private long windowMs;
    private String severity;

    @Column(length = 1000)
    private String details;

    private Instant timestamp;

    @PrePersist
    public void prePersist() { 
    	if (timestamp == null) timestamp = Instant.now();
    	}

    public Long getId()  { 
    	return id; 
    	}
    public String getThreatType() { 
    	return threatType; 
    	}
    public String getSourceIp() { 
    	return sourceIp; 
    	}
    public String getSourceMac() { 
    	return sourceMac; 
    	}
    public String getDestIp()  { 
    	return destIp; 
    	}
    public String getDestMac()  { 
    	return destMac; 
    	}
    public String getProtocol()  { 
    	return protocol; 
    	}
    public String getRequestType() { 
    	return requestType;
    	}
    public int getPacketCount() { 
    	return packetCount; 
    	}
    public long getWindowMs() { 
    	return windowMs; 
    	}
    public String getSeverity() { 
    	return severity; 
    	}
    public String getDetails(){ 
    	return details;
    	}
    public Instant getTimestamp() { 
    	return timestamp; 
    	}

    public void setThreatType(String v){ 
    	threatType = v;
    	}
    public void setSourceIp(String v) { 
    	sourceIp = v; 
    	}
    public void setSourceMac(String v) { 
    	sourceMac = v;
    	}
    public void setDestIp(String v) { 
    	destIp  = v;
    	}
    public void setDestMac(String v) { 
    	destMac = v; 
    	}
    public void setProtocol(String v) { 
    	protocol = v; 
    	}
    public void setRequestType(String v) { 
    	requestType = v; 
    	}
    public void setPacketCount(int v) { 
    	packetCount = v; 
    	}
    public void setWindowMs(long v) { 
    	windowMs = v; 
    	}
    public void setSeverity(String v) { 
    	severity = v; 
    	}
    public void setDetails(String v) { 
    	details  = v; 
    	}
    public void setTimestamp(Instant v){ 
    	timestamp = v; 
    	}
}