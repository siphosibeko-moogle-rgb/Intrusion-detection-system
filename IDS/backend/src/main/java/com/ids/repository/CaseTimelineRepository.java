package com.ids.repository;

import com.ids.entity.CaseTimelineEntry;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CaseTimelineRepository extends JpaRepository<CaseTimelineEntry, Long> {

    // Full chronological history for a case, oldest first for timeline display.
    List<CaseTimelineEntry> findByCaseIdOrderByOccurredAtAsc(Long caseId);
}