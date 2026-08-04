package com.ids.repository;

import com.ids.entity.TriageVerdictEntity;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface TriageVerdictRepository extends JpaRepository<TriageVerdictEntity, Long> {

    Optional<TriageVerdictEntity> findBySourceIpAndThreatType(String sourceIp, String threatType);

    List<TriageVerdictEntity> findByOrderByAnalysedAtDesc(Pageable pageable);

    /**
     * Atomic upsert on (source_ip, threat_type) — same ON CONFLICT pattern as
     * AlertSummaryRepository.upsert(). One verdict per key; a re-sweep always
     * overwrites rather than duplicating.
     */
    @Query(value = """
        INSERT INTO triage_verdict
            (source_ip, threat_type, confidence, classification, reasoning, recommendation, model, analysed_at)
        VALUES
            (:sourceIp, :threatType, :confidence, :classification, :reasoning, :recommendation, :model, :analysedAt)
        ON CONFLICT (source_ip, threat_type)
        DO UPDATE SET
            confidence     = EXCLUDED.confidence,
            classification = EXCLUDED.classification,
            reasoning      = EXCLUDED.reasoning,
            recommendation = EXCLUDED.recommendation,
            model          = EXCLUDED.model,
            analysed_at    = EXCLUDED.analysed_at
        RETURNING *
        """, nativeQuery = true)
    TriageVerdictEntity upsert(
        @Param("sourceIp")       String  sourceIp,
        @Param("threatType")     String  threatType,
        @Param("confidence")     int     confidence,
        @Param("classification") String  classification,
        @Param("reasoning")      String  reasoning,
        @Param("recommendation") String  recommendation,
        @Param("model")          String  model,
        @Param("analysedAt")     Instant analysedAt
    );
}
