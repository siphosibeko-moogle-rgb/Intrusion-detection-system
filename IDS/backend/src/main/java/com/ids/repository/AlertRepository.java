package com.ids.repository;

import com.ids.model.Alert;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import java.time.Instant;
import java.util.List;

public interface AlertRepository extends JpaRepository<Alert, Long> {
    List<Alert> findTop100ByOrderByTimestampDesc();
    List<Alert> findBySeverityOrderByTimestampDesc(String severity);
    List<Alert> findByThreatTypeOrderByTimestampDesc(String threatType);
    List<Alert> findBySourceIpOrderByTimestampDesc(String sourceIp);
    List<Alert> findBySourceMacOrderByTimestampDesc(String sourceMac);
    List<Alert> findByTimestampAfterOrderByTimestampDesc(Instant since);
    List<Alert> findBySourceIpOrderByTimestampAsc(String sourceIp);

    @Query("SELECT a.threatType, COUNT(a) FROM Alert a GROUP BY a.threatType ORDER BY COUNT(a) DESC")
    List<Object[]> countByThreatType();

    @Query("SELECT a.severity, COUNT(a) FROM Alert a GROUP BY a.severity")
    List<Object[]> countBySeverity();

    @Query("SELECT a.sourceIp, a.sourceMac, COUNT(a) FROM Alert a GROUP BY a.sourceIp, a.sourceMac ORDER BY COUNT(a) DESC")
    List<Object[]> topAttackers();
    
 // Fetch distinct flagged IPs with hit count and latest timestamp
    @Query("""
        SELECT a.sourceIp, a.sourceMac, a.threatType, a.protocol,
               COUNT(a) as hits, MAX(a.timestamp) as lastSeen
        FROM Alert a
        WHERE a.threatType IN ('UNKNOWN_IP', 'OUTSIDE_SUBNET')
        GROUP BY a.sourceIp, a.sourceMac, a.threatType, a.protocol
        ORDER BY hits DESC
        """)
    List<Object[]> findFlaggedIpSummary();

    long countBySeverity(String severity);
}