package com.ids.service;

import com.ids.enums.EngineKeyStatus;

import java.time.Duration;
import java.time.Instant;

/**
 * Liveness is derived from engine_keys.last_seen_at at render time — never
 * stored, and no background job flips agents OFFLINE. These two thresholds
 * are the single source of truth for every view that shows liveness.
 */
public final class SensorLiveness {

    /** last_seen_at within this window => ONLINE. */
    public static final Duration ONLINE_WITHIN = Duration.ofMinutes(2);

    /** within this window (but past ONLINE) => STALE; older or never => OFFLINE. */
    public static final Duration STALE_WITHIN = Duration.ofMinutes(15);

    private SensorLiveness() {}

    /** ONLINE / STALE / OFFLINE for ACTIVE keys; "n/a" for PENDING/REVOKED. */
    public static String of(EngineKeyStatus status, Instant lastSeenAt, Instant now) {
        if (status != EngineKeyStatus.ACTIVE) return "n/a";
        if (lastSeenAt == null) return "OFFLINE";
        Duration age = Duration.between(lastSeenAt, now);
        if (age.compareTo(ONLINE_WITHIN) <= 0) return "ONLINE";
        if (age.compareTo(STALE_WITHIN)  <= 0) return "STALE";
        return "OFFLINE";
    }

    /** "never", "just now", "3m ago", "2h ago", "5d ago". */
    public static String relative(Instant lastSeenAt, Instant now) {
        if (lastSeenAt == null) return "never";
        long s = Math.max(0, Duration.between(lastSeenAt, now).getSeconds());
        if (s < 60)    return "just now";
        if (s < 3600)  return (s / 60)    + "m ago";
        if (s < 86400) return (s / 3600)  + "h ago";
        return (s / 86400) + "d ago";
    }
}
