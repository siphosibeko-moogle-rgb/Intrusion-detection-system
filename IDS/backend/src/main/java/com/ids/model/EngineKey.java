package com.ids.model;

import com.ids.enums.EngineKeyStatus;
import jakarta.persistence.*;

import java.time.Instant;
import java.util.UUID;

/**
 * A per-engine API key. Only a SHA-256 hash of the key is stored — the raw
 * key exists in memory once, at approval time, and is shown exactly once.
 * keyHash/keyPrefix stay null while the request is PENDING (no key material
 * is generated until an admin approves).
 */
@Entity
@Table(name = "engine_keys",
       indexes = {
           @Index(name = "idx_engine_keys_owner",  columnList = "owner_id"),
           @Index(name = "idx_engine_keys_status", columnList = "status")
       })
public class EngineKey {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "owner_id", nullable = false)
    private User owner;

    @Column(nullable = false)
    private String name;

    @Column(name = "key_hash", unique = true)
    private String keyHash;

    @Column(name = "key_prefix", length = 8)
    private String keyPrefix;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private EngineKeyStatus status;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "approved_at")
    private Instant approvedAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    // Sensor liveness — advanced on successful ingest auth, throttled to
    // ~30s granularity (see EngineKeyService.authenticate). Null until the
    // key has ingested at least once.
    @Column(name = "last_seen_at")
    private Instant lastSeenAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "approved_by")
    private User approvedBy;

    public EngineKey() {}

    public EngineKey(User owner, String name) {
        this.owner     = owner;
        this.name      = name;
        this.status    = EngineKeyStatus.PENDING;
        this.createdAt = Instant.now();
    }

    public UUID            getId()         { return id; }
    public User            getOwner()      { return owner; }
    public String          getName()       { return name; }
    public String          getKeyHash()    { return keyHash; }
    public String          getKeyPrefix()  { return keyPrefix; }
    public EngineKeyStatus getStatus()     { return status; }
    public Instant         getCreatedAt()  { return createdAt; }
    public Instant         getApprovedAt() { return approvedAt; }
    public Instant         getRevokedAt()  { return revokedAt; }
    public Instant         getLastSeenAt() { return lastSeenAt; }
    public User            getApprovedBy() { return approvedBy; }

    public void setKeyHash(String keyHash)            { this.keyHash = keyHash; }
    public void setKeyPrefix(String keyPrefix)        { this.keyPrefix = keyPrefix; }
    public void setStatus(EngineKeyStatus status)     { this.status = status; }
    public void setApprovedAt(Instant approvedAt)     { this.approvedAt = approvedAt; }
    public void setRevokedAt(Instant revokedAt)       { this.revokedAt = revokedAt; }
    public void setLastSeenAt(Instant lastSeenAt)     { this.lastSeenAt = lastSeenAt; }
    public void setApprovedBy(User approvedBy)        { this.approvedBy = approvedBy; }
}
