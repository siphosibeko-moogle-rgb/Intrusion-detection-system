package com.ids.service;

import com.ids.config.TriageProperties;
import com.ids.model.AlertSummary;
import com.ids.repository.AlertSummaryKeyProjection;
import com.ids.repository.AlertSummaryRepository;
import com.ids.repository.TriageVerdictRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

/**
 * Fires the AI triage sweep. Deliberately @Scheduled — NOT @Async and NOT an
 * @EventListener/@TransactionalEventListener off AlertService.save().
 * @EnableAsync is not present on BackendApplication, so an @Async method
 * here would silently run SYNCHRONOUSLY on the caller's thread — i.e. on the
 * ingest request thread, which is exactly what must never happen.
 * @EnableScheduling is already on (drives the throttle cleanup task), so
 * this class needs no extra enabling annotation, and it runs on Spring's own
 * scheduler thread, never the ingest path.
 */
@Component
public class AiTriageSweepScheduler {

    private static final Logger log = LoggerFactory.getLogger(AiTriageSweepScheduler.class);

    private final TriageProperties props;
    private final AlertSummaryRepository summaryRepo;
    private final TriageVerdictRepository verdictRepo;
    private final AiTriageService triageService;

    /**
     * High-water mark on AlertSummary.lastSeen. Each sweep only fetches
     * summaries newer than this, then advances it to the last (newest)
     * summary the SCAN actually returned — never further — so a batch
     * capped by max-actors-per-sweep can never permanently skip the
     * overflow; it's simply picked up on a later sweep once the mark
     * catches up to it.
     */
    private volatile Instant highWaterMark = Instant.EPOCH;

    public AiTriageSweepScheduler(TriageProperties props,
                                  AlertSummaryRepository summaryRepo,
                                  TriageVerdictRepository verdictRepo,
                                  AiTriageService triageService) {
        this.props = props;
        this.summaryRepo = summaryRepo;
        this.verdictRepo = verdictRepo;
        this.triageService = triageService;
    }

    @Scheduled(fixedDelayString = "${ids.ai-triage.sweep-interval-ms:15000}")
    public void sweep() {
        if (!props.enabled()) return;

        // The SCAN uses a closed projection (AlertSummaryKeyProjection), not
        // the full AlertSummary entity — it must never fail to hydrate a
        // row, or the high-water mark could never advance and every future
        // sweep would keep re-hitting the same failure forever. If it does
        // fail regardless (e.g. a DB connectivity blip), log and bail
        // without touching the mark — the next tick retries from the same
        // point, which is correct for a transient failure.
        List<AlertSummaryKeyProjection> batch;
        try {
            batch = summaryRepo.findByLastSeenAfterOrderByLastSeenAsc(
                highWaterMark, PageRequest.of(0, Math.max(1, props.maxActorsPerSweep())));
        } catch (Exception e) {
            log.warn("[AiTriage] Sweep candidate scan failed, will retry next tick: {}", e.toString());
            return;
        }
        if (batch.isEmpty()) return;

        for (AlertSummaryKeyProjection key : batch) {
            try {
                // Per-candidate full-entity fetch is deliberately INSIDE
                // this try/catch: a legacy/malformed row (e.g. a NULL
                // packet_count/window_ms — nullable at the DB level, but
                // primitive int/long on the entity) fails to hydrate here,
                // not in the scan above, so it only ever costs this one
                // candidate — never the batch, never the high-water mark.
                AlertSummary summary = summaryRepo
                    .findBySourceIpAndThreatType(key.getSourceIp(), key.getThreatType())
                    .orElse(null);
                if (summary == null) continue; // deleted between scan and now

                boolean needsAnalysis = verdictRepo
                    .findBySourceIpAndThreatType(summary.getSourceIp(), summary.getThreatType())
                    .map(v -> v.getAnalysedAt().isBefore(summary.getLastSeen()))
                    .orElse(true);

                if (needsAnalysis) {
                    triageService.analyze(summary);
                }
            } catch (Exception e) {
                log.warn("[AiTriage] Sweep failed for {}/{}: {}",
                    key.getSourceIp(), key.getThreatType(), e.toString());
            }
        }

        highWaterMark = batch.get(batch.size() - 1).getLastSeen();
    }
}
