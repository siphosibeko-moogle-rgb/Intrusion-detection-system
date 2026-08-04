package com.ids.entity;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "triage_verdict",
       uniqueConstraints = {
           @UniqueConstraint(name = "uq_triage_ip_type",
                              columnNames = {"source_ip", "threat_type"})
       },
       indexes = {
           @Index(name = "idx_triage_analysed_at", columnList = "analysed_at")
       })
public class TriageVerdictEntity {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "source_ip", nullable = false, length = 64)
    private String sourceIp;

    @Column(name = "threat_type", nullable = false, length = 64)
    private String threatType;

    @Column(nullable = false)
    private int confidence;

    @Column(nullable = false, length = 32)
    private String classification;

    @Column(length = 500)
    private String reasoning;

    @Column(length = 300)
    private String recommendation;

    @Column(length = 32)
    private String model;

    @Column(name = "analysed_at", nullable = false)
    private Instant analysedAt;

    public Long getId() { return id; }
    public String getSourceIp() { return sourceIp; }
    public String getThreatType() { return threatType; }
    public int getConfidence() { return confidence; }
    public String getClassification() { return classification; }
    public String getReasoning() { return reasoning; }
    public String getRecommendation() { return recommendation; }
    public String getModel() { return model; }
    public Instant getAnalysedAt() { return analysedAt; }

    public void setId(Long v) { id = v; }
    public void setSourceIp(String v) { sourceIp = v; }
    public void setThreatType(String v) { threatType = v; }
    public void setConfidence(int v) { confidence = v; }
    public void setClassification(String v) { classification = v; }
    public void setReasoning(String v) { reasoning = v; }
    public void setRecommendation(String v) { recommendation = v; }
    public void setModel(String v) { model = v; }
    public void setAnalysedAt(Instant v) { analysedAt = v; }
}
