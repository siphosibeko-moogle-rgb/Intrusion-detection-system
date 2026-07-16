package com.ids.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
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
           			columnList = "threatType"),
           @Index(name = "idx_alert_engine_key",
           			columnList = "engine_key_id")
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

    // ── Confidence / provenance (populated by the engine since rule v2.0;
    //    null on rows ingested before these columns existed) ─────────────
    private Integer confidenceScore;

    @Column(length = 500)
    private String confidenceReason;

    private String detectedBy;
    private String ruleVersion;
    private String mitreAttack;

    // ── Throttle dedupe (trusted sources) ────────────────────────────────
    // A SUPPRESSed repeat bumps these on the open alert instead of
    // inserting a new row. Rows from before these columns existed are
    // backfilled to 1 by db/alert_throttle_schema.sql.
    private Integer occurrenceCount = 1;
    private Instant lastSeen;

    // ── Analyst verification / false-positive tracking ──────────────────
    // UNVERIFIED → CONFIRMED | FALSE_POSITIVE. Feeds accuracy reporting and
    // gives any future ML pipeline labelled training data.
    @Column(length = 20)
    private String verificationStatus = "UNVERIFIED";

    private String verifiedBy;
    private Instant verifiedAt;

    // ── Sensor attribution ───────────────────────────────────────────────
    // Which engine key ingested this alert. Set server-side from the
    // authenticated X-Engine-Key — never from the request body. Nullable:
    // rows from before this column existed have no source and are not
    // backfilled. @JsonIgnore keeps the REST/WS JSON shape unchanged for
    // the desktop client.
    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "engine_key_id")
    private EngineKey engineKey;

    @PrePersist
    public void prePersist() {
    	if (timestamp == null) timestamp = Instant.now();
    	if (occurrenceCount == null) occurrenceCount = 1;
    	if (lastSeen == null) lastSeen = timestamp;
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

    public Integer getOccurrenceCount()            { return occurrenceCount; }
    public void setOccurrenceCount(Integer v)      { occurrenceCount = v; }
    public Instant getLastSeen()                   { return lastSeen; }
    public void setLastSeen(Instant v)             { lastSeen = v; }

    public Integer getConfidenceScore()            { return confidenceScore; }
    public void setConfidenceScore(Integer v)      { confidenceScore = v; }
    public String getConfidenceReason()            { return confidenceReason; }
    public void setConfidenceReason(String v)      { confidenceReason = v; }
    public String getDetectedBy()                  { return detectedBy; }
    public void setDetectedBy(String v)            { detectedBy = v; }
    public String getRuleVersion()                 { return ruleVersion; }
    public void setRuleVersion(String v)           { ruleVersion = v; }
    public String getMitreAttack()                 { return mitreAttack; }
    public void setMitreAttack(String v)           { mitreAttack = v; }
    public String getVerificationStatus()          { return verificationStatus; }
    public void setVerificationStatus(String v)    { verificationStatus = v; }
    public String getVerifiedBy()                  { return verifiedBy; }
    public void setVerifiedBy(String v)            { verifiedBy = v; }
    public Instant getVerifiedAt()                 { return verifiedAt; }
    public void setVerifiedAt(Instant v)           { verifiedAt = v; }

    @JsonIgnore
    public EngineKey getEngineKey()                { return engineKey; }
    public void setEngineKey(EngineKey v)          { engineKey = v; }
}