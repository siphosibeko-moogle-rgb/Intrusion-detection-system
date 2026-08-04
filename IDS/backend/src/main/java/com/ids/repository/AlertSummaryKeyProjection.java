package com.ids.repository;

import java.time.Instant;

/**
 * Closed projection over AlertSummary's natural key + lastSeen only.
 *
 * AiTriageSweepScheduler's candidate scan uses this instead of the full
 * AlertSummary entity so it can never fail to hydrate a row: packet_count
 * and window_ms are nullable at the DB level (pre-existing, no NOT NULL
 * constraint) but their entity fields are primitive int/long, so a legacy or
 * manually-inserted row with either NULL throws IllegalArgumentException
 * when Hibernate tries to materialize a full AlertSummary. A closed
 * projection generates a SELECT of only these three columns, sidestepping
 * that entirely — the scan can never be poisoned by a row it doesn't
 * actually need to read.
 */
public interface AlertSummaryKeyProjection {
    String  getSourceIp();
    String  getThreatType();
    Instant getLastSeen();
}
