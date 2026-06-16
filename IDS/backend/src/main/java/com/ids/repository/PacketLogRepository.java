package com.ids.repository;

import com.ids.model.PacketLog;
import org.springframework.data.jpa.repository.JpaRepository;
import java.time.Instant;
import java.util.List;

public interface PacketLogRepository extends JpaRepository<PacketLog, Long> {
    List<PacketLog> findBySourceIpOrderByCapturedAtDesc(String ip);
    List<PacketLog> findBySourceMacOrderByCapturedAtDesc(String mac);
    List<PacketLog> findByCaseIdOrderByCapturedAtDesc(Long caseId);
    List<PacketLog> findByThreatTypeOrderByCapturedAtDesc(String type);
    List<PacketLog> findByCapturedAtAfterOrderByCapturedAtDesc(Instant since);
    List<PacketLog> findTop200ByOrderByCapturedAtDesc();
}