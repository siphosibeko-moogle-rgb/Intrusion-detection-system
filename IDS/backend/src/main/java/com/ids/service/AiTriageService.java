package com.ids.service;

import com.ids.config.TriageProperties;
import com.ids.dto.AlertSummaryDTO;
import com.ids.dto.IpProfileDTO;
import com.ids.dto.TriageEvidence;
import com.ids.dto.TriageVerdict;
import com.ids.enums.TriageClassification;
import com.ids.model.AlertSummary;
import com.ids.repository.AlertRepository;
import com.ids.repository.TriageVerdictRepository;
import com.ids.util.CidrUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

/**
 * AI Security Analyst — triage only. Scores how likely an alert is a true
 * positive and explains why; never blocks, quarantines, firewalls, or
 * mutates any security state. Called only from AiTriageSweepScheduler's
 * @Scheduled sweep — never from AlertService.save() / the ingest path.
 */
@Service
public class AiTriageService {

    private static final Logger log = LoggerFactory.getLogger(AiTriageService.class);

    private final TriageProperties props;
    private final AlertService alertService;
    private final AlertRepository alertRepository;
    private final TriageVerdictRepository verdictRepository;
    private final OrgWhitelistService whitelistService;
    private final TrustedNetworkService trustedNetworkService;
    private final HeuristicLlmClient heuristicClient;
    private final LlmClient activeLlmClient;
    private final SimpMessagingTemplate ws;

    public AiTriageService(TriageProperties props,
                           AlertService alertService,
                           AlertRepository alertRepository,
                           TriageVerdictRepository verdictRepository,
                           OrgWhitelistService whitelistService,
                           TrustedNetworkService trustedNetworkService,
                           HeuristicLlmClient heuristicClient,
                           @Qualifier("activeLlmClient") LlmClient activeLlmClient,
                           SimpMessagingTemplate ws) {
        this.props = props;
        this.alertService = alertService;
        this.alertRepository = alertRepository;
        this.verdictRepository = verdictRepository;
        this.whitelistService = whitelistService;
        this.trustedNetworkService = trustedNetworkService;
        this.heuristicClient = heuristicClient;
        this.activeLlmClient = activeLlmClient;
        this.ws = ws;
    }

    /**
     * Returns null when the feature is off (caller does nothing further).
     * Otherwise ALWAYS returns a verdict — any failure past the enabled
     * check is caught here and recorded as a NEEDS_REVIEW fallback rather
     * than propagating, so one bad actor can never abort a sweep batch.
     *
     * NOTE: intentionally plain @Transactional, not readOnly=true — this
     * method persists the verdict (native upsert) and mirrors confidence
     * onto the matching alert row (native update); Postgres rejects writes
     * on a JDBC-readOnly connection, so a readOnly transaction here would
     * make every real call fail and silently fall through to the catch
     * block's fallback on every single analysis.
     */
    @Transactional
    public TriageVerdict analyze(AlertSummary summary) {
        if (!props.enabled()) return null;

        try {
            return doAnalyze(summary);
        } catch (Exception e) {
            log.warn("[AiTriage] analyze() failed for {}/{}: {} — recording a NEEDS_REVIEW fallback.",
                summary.getSourceIp(), summary.getThreatType(), e.toString());
            TriageVerdict fallback = new TriageVerdict(summary.getSourceIp(), summary.getThreatType(),
                50, TriageClassification.NEEDS_REVIEW,
                "Triage failed: " + e.getMessage(), "Manual review required.",
                "fallback", Instant.now());
            try {
                persist(fallback);
                ws.convertAndSend("/topic/triage", fallback);
            } catch (Exception persistFailure) {
                log.warn("[AiTriage] Could not persist fallback verdict for {}/{}: {}",
                    summary.getSourceIp(), summary.getThreatType(), persistFailure.toString());
            }
            return fallback;
        }
    }

    private TriageVerdict doAnalyze(AlertSummary summary) {
        String ip = summary.getSourceIp();
        boolean whitelisted = whitelistService.isWhitelisted(ip);
        boolean trustedNetwork = trustedNetworkService.isTrusted(ip);
        boolean severityIsHighOrCritical =
            "HIGH".equals(summary.getSeverity()) || "CRITICAL".equals(summary.getSeverity());

        TriageEvidence evidence = buildEvidence(summary, whitelisted, trustedNetwork);

        // Deterministic pre-check: an obvious trusted-and-not-severe case
        // skips the LLM call entirely (saves tokens / avoids network calls
        // on the common case).
        TriageVerdict verdict = (whitelisted || trustedNetwork) && !severityIsHighOrCritical
            ? heuristicClient.classify(evidence)
            : activeLlmClient.classify(evidence);

        persist(verdict);
        mirrorOntoAlerts(verdict);
        ws.convertAndSend("/topic/triage", verdict);
        return verdict;
    }

    private TriageEvidence buildEvidence(AlertSummary summary, boolean whitelisted, boolean trustedNetwork) {
        IpProfileDTO profile = alertService.buildIpProfile(summary.getSourceIp());

        List<AlertSummaryDTO> recent = profile != null
            ? profile.recentThreats().stream().limit(15).toList()
            : List.of();

        return new TriageEvidence(
            summary.getSourceIp(),
            summary.getThreatType(),
            summary.getSeverity(),
            profile != null ? profile.totalAlerts() : 0,
            profile != null ? profile.targetCount() : 0,
            profile != null ? profile.firstSeen() : summary.getFirstSeen(),
            profile != null ? profile.lastSeen() : summary.getLastSeen(),
            profile != null ? profile.topThreatType() : summary.getThreatType(),
            profile != null ? profile.mostTargetedHost()
                             : (summary.getDestIp() != null ? summary.getDestIp() : "N/A"),
            profile != null ? profile.threatScore() : 0,
            profile != null ? profile.riskLevel() : "LOW",
            profile != null ? profile.protocols() : List.of(),
            recent,
            summary.getOccurrenceCount(),
            summary.getFirstSeen(),
            summary.getLastSeen(),
            whitelisted,
            trustedNetwork,
            isCriticalAsset(summary.getDestIp())
        );
    }

    private boolean isCriticalAsset(String ip) {
        if (ip == null || ip.isBlank()) return false;
        for (String entry : props.criticalAssetList()) {
            if (CidrUtils.matches(ip, entry)) return true;
        }
        return false;
    }

    private void persist(TriageVerdict v) {
        verdictRepository.upsert(v.sourceIp(), v.threatType(), v.confidence(),
            v.classification().name(), v.reasoning(), v.recommendation(), v.model(), v.analysedAt());
    }

    /**
     * Best-effort mirror of the verdict onto the single most recent matching
     * `alerts` row — never verificationStatus, which stays analyst-owned.
     * Same "update the latest matching row" shape as
     * AlertRepository.incrementLatestOccurrence(); a no-op (0 rows) if the
     * raw row has since been cleared is fine, the sidecar table is still
     * the source of truth for the verdict itself.
     */
    private void mirrorOntoAlerts(TriageVerdict v) {
        alertRepository.updateLatestConfidence(v.sourceIp(), v.threatType(), v.confidence(), v.reasoning());
    }
}
