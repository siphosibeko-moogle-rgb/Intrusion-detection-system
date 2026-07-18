package com.ids.repository;

import com.ids.model.Alert;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Collection;
import java.util.List;

public interface AlertRepository extends JpaRepository<Alert, Long> {

    List<Alert> findTop100ByOrderByTimestampDesc();

    // All list queries are capped: raw alerts are unbounded (one row per
    // event, forever), so an uncapped filter — or sinceMs=0 — would stream
    // the whole table into one JSON response.
    List<Alert> findTop500BySeverityOrderByTimestampDesc(String severity);

    List<Alert> findTop500ByThreatTypeOrderByTimestampDesc(String threatType);

    List<Alert> findBySourceIpOrderByTimestampAsc(String sourceIp);

    List<Alert> findTop500BySourceMacOrderByTimestampDesc(String sourceMac);

    List<Alert> findTop1000ByTimestampAfterOrderByTimestampDesc(Instant since);

    List<Alert> findTop500BySourceIpOrderByTimestampDesc(String sourceIp);

    long countBySeverity(String severity);

    // Per-sensor alert counts for the status pages — one grouped query
    // regardless of key count (never a count() loop per key). Grouping on
    // the FK itself needs no join to engine_keys.
    @Query("SELECT a.engineKey.id, COUNT(a) FROM Alert a WHERE a.engineKey IS NOT NULL GROUP BY a.engineKey.id")
    List<Object[]> countPerEngineKey();

    // Same, scoped to one owner's keys for /engines.
    @Query("SELECT a.engineKey.id, COUNT(a) FROM Alert a WHERE a.engineKey.owner.id = :ownerId GROUP BY a.engineKey.id")
    List<Object[]> countPerEngineKeyForOwner(@Param("ownerId") Long ownerId);

    @Query("""
        SELECT a.threatType, COUNT(a)
        FROM Alert a
        GROUP BY a.threatType
        ORDER BY COUNT(a) DESC
    """)
    List<Object[]> countByThreatType();

    @Query("""
        SELECT a.severity, COUNT(a)
        FROM Alert a
        GROUP BY a.severity
    """)
    List<Object[]> countBySeverityGrouped();

    @Query("""
        SELECT a.sourceIp, a.sourceMac, COUNT(a)
        FROM Alert a
        GROUP BY a.sourceIp, a.sourceMac
        ORDER BY COUNT(a) DESC
    """)
    List<Object[]> topAttackers();

    /**
     * One row per flagged source IP (UNKNOWN_IP / OUTSIDE_SUBNET).
     *
     * FIX: this used to GROUP BY (sourceIp, sourceMac, threatType, protocol),
     * so one device showed up as a separate "duplicate" row for every distinct
     * MAC/threat/protocol combination it was seen with — the Flagged IPs table
     * filled with repeats of the same IP. Group by IP alone: merge the threat
     * types and protocols into comma lists, sum the hits, take the latest
     * sighting and the highest severity. Native SQL for STRING_AGG and the
     * severity ranking, same as findAlertGroupsBySourceIp below.
     *
     * Columns: 0=ip, 1=mac, 2=threatTypes, 3=protocols, 4=hits,
     *          5=lastSeen (java.sql.Timestamp — native query, not Instant),
     *          6=severityRank (4=CRITICAL … 1=LOW, 0=other).
     */
    @Query(value = """
        SELECT
            source_ip AS ip,
            MAX(source_mac) AS mac,
            STRING_AGG(DISTINCT threat_type, ', ') AS threatTypes,
            STRING_AGG(DISTINCT protocol, ', ') AS protocols,
            COUNT(*) AS hits,
            MAX(timestamp) AS lastSeen,
            MAX(
                CASE severity
                    WHEN 'CRITICAL' THEN 4
                    WHEN 'HIGH' THEN 3
                    WHEN 'MEDIUM' THEN 2
                    WHEN 'LOW' THEN 1
                    ELSE 0
                END
            ) AS severityRank
        FROM alerts
        WHERE threat_type IN ('UNKNOWN_IP', 'OUTSIDE_SUBNET')
        GROUP BY source_ip
        ORDER BY COUNT(*) DESC
        """, nativeQuery = true)
    List<Object[]> findFlaggedIpSummary();

    /**
     * Groups alerts by source IP for the Investigation panel.
     */
    @Query(value = """
        SELECT
            source_ip AS sourceIp,
            MAX(source_mac) AS sourceMac,
            COUNT(*) AS alertCount,
            MIN(timestamp) AS firstSeen,
            MAX(timestamp) AS lastSeen,
            STRING_AGG(DISTINCT threat_type, ', ') AS threatTypes,
            MAX(
                CASE severity
                    WHEN 'CRITICAL' THEN 4
                    WHEN 'HIGH' THEN 3
                    WHEN 'MEDIUM' THEN 2
                    WHEN 'LOW' THEN 1
                    ELSE 0
                END
            ) AS severityRank
        FROM alerts
        GROUP BY source_ip
        ORDER BY COUNT(*) DESC
        """, nativeQuery = true)
    List<AlertGroupProjection> findAlertGroupsBySourceIp();
    
    /**
     * Powers "View Conversation" — alerts recorded between two IPs,
     * regardless of which one was source vs destination on a given alert.
     * Ordered newest-first so a Pageable cap keeps the most RECENT rows
     * (a chatty pair could have unbounded history); the controller
     * reverses the page back to chronological order for display.
     */
    @Query("SELECT a FROM Alert a " +
           "WHERE (a.sourceIp = :ip1 AND a.destIp = :ip2) " +
           "   OR (a.sourceIp = :ip2 AND a.destIp = :ip1) " +
           "ORDER BY a.timestamp DESC")
    List<Alert> findConversation(@Param("ip1") String ip1, @Param("ip2") String ip2,
                                 org.springframework.data.domain.Pageable pageable);

    // ── Threat-actors batch aggregates ───────────────────────────────────
    // One grouped query per statistic for ALL ranked IPs at once — replaces
    // the old per-IP buildIpProfile() calls (1 + N queries, each loading an
    // attacker's ENTIRE alert history just to count severities).

    @Query("""
        SELECT a.sourceIp, a.severity, COUNT(a)
        FROM Alert a
        WHERE a.sourceIp IN :ips
        GROUP BY a.sourceIp, a.severity
    """)
    List<Object[]> countSeverityBySourceIps(@Param("ips") Collection<String> ips);

    @Query("""
        SELECT a.sourceIp, a.threatType, COUNT(a)
        FROM Alert a
        WHERE a.sourceIp IN :ips
        GROUP BY a.sourceIp, a.threatType
    """)
    List<Object[]> countThreatTypeBySourceIps(@Param("ips") Collection<String> ips);

    /**
     * Throttle SUPPRESS path: fold a deduped repeat into the most recent
     * matching alert instead of inserting a new row. Returns 0 when no
     * matching alert exists yet (caller falls back to a normal insert).
     */
    @Modifying
    @Query(value = """
        UPDATE alerts
           SET occurrence_count = COALESCE(occurrence_count, 1) + 1,
               last_seen        = :seenAt
         WHERE id = (SELECT id FROM alerts
                     WHERE source_ip = :sourceIp AND threat_type = :threatType
                     ORDER BY timestamp DESC
                     LIMIT 1)
        """, nativeQuery = true)
    int incrementLatestOccurrence(@Param("sourceIp")   String sourceIp,
                                  @Param("threatType") String threatType,
                                  @Param("seenAt")     Instant seenAt);
}