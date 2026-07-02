package com.ids.entity;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * Immutable audit log entry for a case.
 *
 * Think of it like a Git commit: once written it is never updated.
 * The UI renders these as a vertical timeline ordered by occurred_at.
 *
 * Why store event_kind as a VARCHAR and not a Java enum directly?
 * Postgres enums are painful to migrate. Storing the string keeps
 * Flyway migrations simple — just add new event kinds without DDL.
 */
@Entity
@Table(name = "case_timeline",
       indexes = {
           @Index(name = "idx_case_timeline_case_id",  columnList = "case_id"),
           @Index(name = "idx_case_timeline_occurred", columnList = "occurred_at")
       })
public class CaseTimelineEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "case_id", nullable = false)
    private Long caseId;

    // One of: CASE_OPENED, ALERT_LINKED, STATUS_CHANGED, NOTE_ADDED,
    //         ANALYST_ACTION, IP_WHITELISTED, IP_BLOCKED, CASE_CLOSED
    @Column(name = "event_kind", nullable = false, length = 50)
    private String eventKind;

    @Column(length = 100)
    private String actor;   // username of the analyst (or "system")

    @Column(columnDefinition = "TEXT")
    private String detail;  // human-readable one-liner

    @Column(name = "ref_id")
    private Long refId;     // optional: alert.id or note.id for deep-link

    @Column(name = "occurred_at", nullable = false, updatable = false)
    private Instant occurredAt = Instant.now();

    // ── factory helpers ────────────────────────────────────
    public static CaseTimelineEntry of(Long caseId, String kind,
                                       String actor, String detail) {
        CaseTimelineEntry e = new CaseTimelineEntry();
        e.caseId     = caseId;
        e.eventKind  = kind;
        e.actor      = actor;
        e.detail     = detail;
        e.occurredAt = Instant.now();
        return e;
    }

    public static CaseTimelineEntry of(Long caseId, String kind,
                                       String actor, String detail, Long refId) {
        CaseTimelineEntry e = of(caseId, kind, actor, detail);
        e.refId = refId;
        return e;
    }

    // ── getters / setters ──────────────────────────────────

    public Long    getId()         { return id; }
    public Long    getCaseId()     { return caseId; }
    public String  getEventKind()  { return eventKind; }
    public String  getActor()      { return actor; }
    public String  getDetail()     { return detail; }
    public Long    getRefId()      { return refId; }
    public Instant getOccurredAt() { return occurredAt; }

    public void setId(Long id)              { this.id = id; }
    public void setCaseId(Long caseId)      { this.caseId = caseId; }
    public void setEventKind(String kind)   { this.eventKind = kind; }
    public void setActor(String actor)      { this.actor = actor; }
    public void setDetail(String detail)    { this.detail = detail; }
    public void setRefId(Long refId)        { this.refId = refId; }
    public void setOccurredAt(Instant t)    { this.occurredAt = t; }
}