package com.ids.repository;

import com.ids.model.ForensicCase;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;

public interface ForensicCaseRepository extends JpaRepository<ForensicCase, Long> {
    Optional<ForensicCase> findByCaseNumber(String caseNumber);
    List<ForensicCase> findByStatusOrderByOpenedAtDesc(String status);
    List<ForensicCase> findByAssignedToOrderByOpenedAtDesc(String username);
    List<ForensicCase> findBySuspectIpOrderByOpenedAtDesc(String ip);
    // Batch variant for getAlertGroupsForCaseCreation — one query for every
    // group's IP instead of one per group.
    List<ForensicCase> findBySuspectIpInOrderByOpenedAtDesc(java.util.Collection<String> ips);
    List<ForensicCase> findBySuspectMacOrderByOpenedAtDesc(String mac);
    List<ForensicCase> findTop50ByOrderByOpenedAtDesc();
}