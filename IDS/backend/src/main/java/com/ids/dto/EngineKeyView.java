package com.ids.dto;

import com.ids.enums.EngineKeyStatus;

import java.time.Instant;

/**
 * Read-only row for the status pages (/engines, /admin/agents).
 * Carries no key material — prefix only, never key_hash or a raw key.
 */
public class EngineKeyView {

    private final String ownerEmail;
    private final String name;
    private final String keyPrefix;
    private final EngineKeyStatus status;
    private final Instant createdAt;
    private final Instant approvedAt;
    private final String liveness;
    private final String lastSeen;
    private final long alertCount;

    public EngineKeyView(String ownerEmail, String name, String keyPrefix,
                         EngineKeyStatus status, Instant createdAt, Instant approvedAt,
                         String liveness, String lastSeen, long alertCount) {
        this.ownerEmail = ownerEmail;
        this.name       = name;
        this.keyPrefix  = keyPrefix;
        this.status     = status;
        this.createdAt  = createdAt;
        this.approvedAt = approvedAt;
        this.liveness   = liveness;
        this.lastSeen   = lastSeen;
        this.alertCount = alertCount;
    }

    public String          getOwnerEmail() { return ownerEmail; }
    public String          getName()       { return name; }
    public String          getKeyPrefix()  { return keyPrefix; }
    public EngineKeyStatus getStatus()     { return status; }
    public Instant         getCreatedAt()  { return createdAt; }
    public Instant         getApprovedAt() { return approvedAt; }
    public String          getLiveness()   { return liveness; }
    public String          getLastSeen()   { return lastSeen; }
    public long            getAlertCount() { return alertCount; }

    /** CSS-safe variant of liveness ("n/a" -> "NA") for badge classes. */
    public String getLivenessClass() {
        return "n/a".equals(liveness) ? "NA" : liveness;
    }
}
