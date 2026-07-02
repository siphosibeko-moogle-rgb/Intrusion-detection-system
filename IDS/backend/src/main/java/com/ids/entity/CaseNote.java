package com.ids.entity;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * Analyst note attached to a forensic case.
 *
 * Why a separate table instead of a JSON blob on ForensicCase?
 * Notes are independently indexed, sortable, and will eventually
 * support editing and soft-delete. A proper table also lets the
 * timeline query join directly against case_notes.id.
 */
@Entity
@Table(name = "case_notes",
       indexes = @Index(name = "idx_case_notes_case_id", columnList = "case_id"))
public class CaseNote {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "case_id", nullable = false)
    private Long caseId;

    @Column(nullable = false, length = 100)
    private String author;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String content;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    @PreUpdate
    public void onUpdate() { this.updatedAt = Instant.now(); }

    // ── getters / setters ──────────────────────────────────

    public Long    getId()        { return id; }
    public Long    getCaseId()    { return caseId; }
    public String  getAuthor()    { return author; }
    public String  getContent()   { return content; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }

    public void setId(Long id)            { this.id = id; }
    public void setCaseId(Long caseId)    { this.caseId = caseId; }
    public void setAuthor(String author)  { this.author = author; }
    public void setContent(String content){ this.content = content; }
    public void setCreatedAt(Instant t)   { this.createdAt = t; }
    public void setUpdatedAt(Instant t)   { this.updatedAt = t; }
}