package com.ids.repository;

import com.ids.model.AlertSummary;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface AlertSummaryRepository extends JpaRepository<AlertSummary, Long> {

    List<AlertSummary> findAllByOrderByLastSeenDesc();
    List<AlertSummary> findBySeverityOrderByLastSeenDesc(String severity);
    List<AlertSummary> findByThreatTypeOrderByLastSeenDesc(String threatType);
    List<AlertSummary> findBySourceIpOrderByLastSeenDesc(String sourceIp);

    /**
     * AiTriageSweepScheduler's candidate SCAN — oldest-of-the-new first, one
     * page capped at max-actors-per-sweep, so the scheduler's high-water
     * mark can always advance to exactly what it fetched with no gaps.
     *
     * Returns the closed projection (see AlertSummaryKeyProjection), not the
     * full entity: this query must never fail to hydrate a row, since a
     * failure here would leave the high-water mark stuck forever, wedging
     * the whole sweep. The full entity is fetched per-candidate afterwards
     * via findBySourceIpAndThreatType, isolated inside the scheduler's
     * per-row try/catch instead.
     */
    List<AlertSummaryKeyProjection> findByLastSeenAfterOrderByLastSeenAsc(Instant since, Pageable pageable);

    /** Full-entity fetch for one candidate selected by the scan above. */
    Optional<AlertSummary> findBySourceIpAndThreatType(String sourceIp, String threatType);

    /**
     * FIX: Added so AlertController.stats() counts from alert_summary
     * instead of the raw alerts table. This makes dashboard counters
     * drop immediately after a summary row is deleted.
     */
    long countBySeverity(String severity);

    /**
     * Atomic upsert. ON CONFLICT resolves the race between concurrent
     * detector threads hitting the same (sourceIp, threatType) pair —
     * Postgres serializes on the unique index's row lock, so no
     * lost-update / duplicate-key race is possible here.
     */
    @Query(value = """
        INSERT INTO alert_summary
            (source_ip, threat_type, severity, source_mac, dest_ip, dest_mac,
             protocol, request_type, details, packet_count, window_ms,
             occurrence_count, first_seen, last_seen)
        VALUES
            (:sourceIp, :threatType, :severity, :sourceMac, :destIp, :destMac,
             :protocol, :requestType, :details, :packetCount, :windowMs,
             1, :timestamp, :timestamp)
        ON CONFLICT (source_ip, threat_type)
        DO UPDATE SET
            occurrence_count = alert_summary.occurrence_count + 1,
            last_seen        = EXCLUDED.last_seen,
            severity         = EXCLUDED.severity,
            source_mac       = EXCLUDED.source_mac,
            dest_ip          = EXCLUDED.dest_ip,
            dest_mac         = EXCLUDED.dest_mac,
            protocol         = EXCLUDED.protocol,
            request_type     = EXCLUDED.request_type,
            details          = EXCLUDED.details,
            packet_count     = EXCLUDED.packet_count,
            window_ms        = EXCLUDED.window_ms
        RETURNING *
        """, nativeQuery = true)
    AlertSummary upsert(
        @Param("sourceIp")    String  sourceIp,
        @Param("threatType")  String  threatType,
        @Param("severity")    String  severity,
        @Param("sourceMac")   String  sourceMac,
        @Param("destIp")      String  destIp,
        @Param("destMac")     String  destMac,
        @Param("protocol")    String  protocol,
        @Param("requestType") String  requestType,
        @Param("details")     String  details,
        @Param("packetCount") int     packetCount,
        @Param("windowMs")    long    windowMs,
        @Param("timestamp")   Instant timestamp
    );
}