package com.ids.model;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * Forensic investigation case.
 * Status: OPEN | INVESTIGATING | CLOSED | ARCHIVED
 */
@Entity
@Table(name = "forensic_cases")
public class ForensicCase {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String caseNumber;

    @Column(nullable = false)
    private String title;

    @Column(length = 2000)
    private String description;

    private String status;
    private String severity;
    private String assignedTo;
    private String createdBy;
    private String suspectIp;
    private String suspectMac;
    private String threatType;
    private Instant openedAt;
    private Instant closedAt;
    private Instant lastUpdated;

    @Column(length = 4000)
    private String findings;

    @PrePersist
    public void prePersist() {
        if (openedAt   == null) openedAt    = Instant.now();
        if (lastUpdated== null) lastUpdated = Instant.now();
        if (status     == null) status      = "OPEN";
    }

    @PreUpdate
    public void preUpdate() { 
    	lastUpdated = Instant.now();
    	}

    public Long getId() { 
    	return id; 
    	}
    public String getCaseNumber() { 
    	return caseNumber; 
    	}
    public String getTitle(){ 
    	return title; 
    	}
    public String getDescription() { 
    	return description; 
    	}
    public String getStatus() { 
    	return status; 
    	}
    public String getSeverity() { 
    	return severity; 
    	}
    public String getAssignedTo(){ 
    	return assignedTo; 
    	}
    public String getCreatedBy() { 
    	return createdBy; }
    public String  getSuspectIp() { 
    	return suspectIp; 
    	}
    public String getSuspectMac()  { 
    	return suspectMac; 
    	}
    public String getThreatType(){
    	return threatType;
}
    public Instant getOpenedAt() { 
    	return openedAt; 
    	}
    public Instant getClosedAt(){ 
    	return closedAt; 
    	}
    public Instant getLastUpdated() { 
    	return lastUpdated; 
    	}
    public String getFindings(){ 
    	return findings; 
    	}

    public void setCaseNumber(String v){ 
    	caseNumber  = v; 
    	}
    public void setTitle(String v){ 
    	title   = v;
    	}
    public void setDescription(String v) { 
    	description = v; 
    	}
    public void setStatus(String v) { 
    	status      = v; 
    	}
    public void setSeverity(String v) { 
    	severity    = v; 
    	}
    public void setAssignedTo(String v){ 
    	assignedTo  = v; 
    	}
    public void setCreatedBy(String v) { 
    	createdBy   = v;
    	}
    public void setSuspectIp(String v) { 
    	suspectIp   = v; 
    	}
    public void setSuspectMac(String v) { 
    	suspectMac  = v; 
    	}
    public void setThreatType(String v) { 
    	threatType  = v; 
    	}
    public void setClosedAt(Instant v) { 
    	closedAt    = v; 
    	}
    public void setFindings(String v) { 
    	findings    = v; 
    	}
}