package com.ids.model;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "forensic_cases")
public class ForensicCase {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String caseNumber;

    @Column(nullable = false)
    private String title;

    @Column(length = 2000)
    private String description;

    @Column(nullable = false)
    private String status = "OPEN";

    @Column(length = 20)
    private String severity;

    private String priority = "MEDIUM";

    private String assignedTo;
    private String createdBy;

    private String suspectIp;
    private String suspectMac;
    private String threatType;

    @Column(name = "alert_count")
    private int alertCount = 0;

    @Column(name = "first_seen")
    private Instant firstSeen;

    @Column(name = "last_seen")
    private Instant lastSeen;

    private Instant openedAt;
    private Instant closedAt;
    private Instant lastUpdated;

    @Column(length = 4000)
    private String findings;

    @PrePersist
    public void prePersist() {
        Instant now = Instant.now();

        if (openedAt == null) openedAt = now;
        if (lastUpdated == null) lastUpdated = now;
        if (firstSeen == null) firstSeen = now;
    }

    @PreUpdate
    public void preUpdate() {
        lastUpdated = Instant.now();
        lastSeen = Instant.now();
    }

    public Long getId() { return id; }

    public String getCaseNumber() { return caseNumber; }
    public void setCaseNumber(String v) { this.caseNumber = v; }

    public String getTitle() { return title; }
    public void setTitle(String v) { this.title = v; }

    public String getDescription() { return description; }
    public void setDescription(String v) { this.description = v; }

    public String getStatus() { return status; }
    public void setStatus(String v) { this.status = v; }

    public String getSeverity() { return severity; }
    public void setSeverity(String v) { this.severity = v; }

    public String getPriority() { return priority; }
    public void setPriority(String v) { this.priority = v; }

    public String getAssignedTo() { return assignedTo; }
    public void setAssignedTo(String v) { this.assignedTo = v; }

    public String getCreatedBy() { return createdBy; }
    public void setCreatedBy(String v) { this.createdBy = v; }

    public String getSuspectIp() { return suspectIp; }
    public void setSuspectIp(String v) { this.suspectIp = v; }

    public String getSuspectMac() { return suspectMac; }
    public void setSuspectMac(String v) { this.suspectMac = v; }

    public String getThreatType() { return threatType; }
    public void setThreatType(String v) { this.threatType = v; }

    public int getAlertCount() { return alertCount; }
    public void setAlertCount(int n) { this.alertCount = n; }

    public Instant getFirstSeen() { return firstSeen; }
    public void setFirstSeen(Instant t) { this.firstSeen = t; }

    public Instant getLastSeen() { return lastSeen; }
    public void setLastSeen(Instant t) { this.lastSeen = t; }

    public Instant getOpenedAt() { return openedAt; }
    public Instant getClosedAt() { return closedAt; }
    public void setClosedAt(Instant v) { this.closedAt = v; }

    public Instant getLastUpdated() { return lastUpdated; }

    public String getFindings() { return findings; }
    public void setFindings(String v) { this.findings = v; }
}