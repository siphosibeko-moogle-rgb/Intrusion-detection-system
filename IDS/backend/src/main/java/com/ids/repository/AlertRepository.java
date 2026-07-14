package com.ids.repository;

import com.ids.model.Alert;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;

public interface AlertRepository extends JpaRepository<Alert, Long> {

    List<Alert> findTop100ByOrderByTimestampDesc();

    List<Alert> findBySeverityOrderByTimestampDesc(String severity);

    List<Alert> findByThreatTypeOrderByTimestampDesc(String threatType);

    List<Alert> findBySourceIpOrderByTimestampDesc(String sourceIp);

    List<Alert> findBySourceIpOrderByTimestampAsc(String sourceIp);

    List<Alert> findBySourceMacOrderByTimestampDesc(String sourceMac);

    List<Alert> findByTimestampAfterOrderByTimestampDesc(Instant since);

    List<Alert> findTop500BySourceIpOrderByTimestampDesc(String sourceIp);

    long countBySeverity(String severity);

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

    @Query("""
        SELECT a.sourceIp, a.sourceMac, a.threatType, a.protocol,
               COUNT(a) as hits, MAX(a.timestamp) as lastSeen
        FROM Alert a
        WHERE a.threatType IN ('UNKNOWN_IP', 'OUTSIDE_SUBNET')
        GROUP BY a.sourceIp, a.sourceMac, a.threatType, a.protocol
        ORDER BY hits DESC
    """)
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
     * Powers "View Conversation" — every alert recorded between two IPs,
     * regardless of which one was source vs destination on a given alert,
     * ordered chronologically so it reads like a timeline of the pair's
     * interaction.
     */
    @Query("SELECT a FROM Alert a " +
           "WHERE (a.sourceIp = :ip1 AND a.destIp = :ip2) " +
           "   OR (a.sourceIp = :ip2 AND a.destIp = :ip1) " +
           "ORDER BY a.timestamp ASC")
    List<Alert> findConversation(@Param("ip1") String ip1, @Param("ip2") String ip2);

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