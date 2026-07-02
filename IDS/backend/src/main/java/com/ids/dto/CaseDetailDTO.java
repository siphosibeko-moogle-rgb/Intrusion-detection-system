package com.ids.dto;

import com.ids.entity.CaseNote;
import com.ids.entity.CaseTimelineEntry;
import com.ids.model.Alert;

import java.time.Instant;
import java.util.List;

/**
 * Aggregated response for the Case Detail panel.
 *
 * Returned by GET /api/forensics/cases/{id}/detail
 *
 * Why one fat DTO instead of 4 separate endpoints?
 * The Case Detail panel opens cold (no pre-loaded data). A single
 * HTTP call avoids 4 round-trips and prevents partial-load race
 * conditions in the JavaFX UI thread.
 *
 * The tradeoff: this object can be large (many alerts). We cap
 * linkedAlerts at 500 on the service side to prevent OOM.
 */
public class CaseDetailDTO {

    // ── Overview ───────────────────────────────────────────
    private Long    id;
    private String  caseNumber;
    private String  title;
    private String  description;
    private String  status;
    private String  priority;
    private String  severity;
    private String  suspectIp;
    private String  suspectMac;
    private String  threatType;
    private String  assignedTo;
    private String  createdBy;
    private Instant openedAt;
    private Instant closedAt;
    private Instant firstSeen;
    private Instant lastSeen;
    private int     alertCount;

    // ── Alerts tab ─────────────────────────────────────────
    private List<Alert> linkedAlerts;     // capped at 500

    // ── Timeline tab ───────────────────────────────────────
    private List<CaseTimelineEntry> timeline;

    // ── Notes tab ──────────────────────────────────────────
    private List<CaseNote> notes;

    // ── Constructor ────────────────────────────────────────
    public CaseDetailDTO() {}

    // ── Getters / Setters ──────────────────────────────────
    public Long    getId()          { return id; }
    public String  getCaseNumber()  { return caseNumber; }
    public String  getTitle()       { return title; }
    public String  getDescription() { return description; }
    public String  getStatus()      { return status; }
    public String  getPriority()    { return priority; }
    public String  getSeverity()    { return severity; }
    public String  getSuspectIp()   { return suspectIp; }
    public String  getSuspectMac()  { return suspectMac; }
    public String  getThreatType()  { return threatType; }
    public String  getAssignedTo()  { return assignedTo; }
    public String  getCreatedBy()   { return createdBy; }
    public Instant getOpenedAt()    { return openedAt; }
    public Instant getClosedAt()    { return closedAt; }
    public Instant getFirstSeen()   { return firstSeen; }
    public Instant getLastSeen()    { return lastSeen; }
    public int     getAlertCount()  { return alertCount; }

    public List<Alert>              getLinkedAlerts() { return linkedAlerts; }
    public List<CaseTimelineEntry>  getTimeline()     { return timeline; }
    public List<CaseNote>           getNotes()        { return notes; }

    public void setId(Long id)                    { this.id = id; }
    public void setCaseNumber(String n)           { this.caseNumber = n; }
    public void setTitle(String t)                { this.title = t; }
    public void setDescription(String d)          { this.description = d; }
    public void setStatus(String s)               { this.status = s; }
    public void setPriority(String p)             { this.priority = p; }
    public void setSeverity(String s)             { this.severity = s; }
    public void setSuspectIp(String ip)           { this.suspectIp = ip; }
    public void setSuspectMac(String mac)         { this.suspectMac = mac; }
    public void setThreatType(String t)           { this.threatType = t; }
    public void setAssignedTo(String a)           { this.assignedTo = a; }
    public void setCreatedBy(String c)            { this.createdBy = c; }
    public void setOpenedAt(Instant t)            { this.openedAt = t; }
    public void setClosedAt(Instant t)            { this.closedAt = t; }
    public void setFirstSeen(Instant t)           { this.firstSeen = t; }
    public void setLastSeen(Instant t)            { this.lastSeen = t; }
    public void setAlertCount(int n)              { this.alertCount = n; }
    public void setLinkedAlerts(List<Alert> a)    { this.linkedAlerts = a; }
    public void setTimeline(List<CaseTimelineEntry> t) { this.timeline = t; }
    public void setNotes(List<CaseNote> n)        { this.notes = n; }
}