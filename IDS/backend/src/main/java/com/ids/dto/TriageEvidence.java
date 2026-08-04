package com.ids.dto;

import java.time.Instant;
import java.util.List;

/**
 * Everything AiTriageService assembles for one (sourceIp, threatType)
 * verdict, built entirely from existing services — never a direct DB query
 * from the triage layer itself.
 */
public record TriageEvidence(
    String sourceIp,
    String threatType,
    String severity,

    // From AlertService.buildIpProfile(sourceIp) — the source's full history.
    long totalAlerts,
    long distinctTargets,
    Instant profileFirstSeen,
    Instant profileLastSeen,
    String topThreatType,
    String mostTargetedHost,
    int threatScore,
    String riskLevel,
    List<String> protocols,
    List<AlertSummaryDTO> recentThreats,

    // From the triggering AlertSummary. The throttle SUPPRESSes repeated
    // alerts from trusted sources before they ever reach the raw `alerts`
    // table, so totalAlerts above can under-count a trusted-but-compromised
    // source. occurrenceCount counts those suppressed repeats too — treat
    // it, not totalAlerts, as the true volume/rate signal.
    int occurrenceCount,
    Instant summaryFirstSeen,
    Instant summaryLastSeen,

    boolean sourceWhitelisted,
    boolean sourceTrustedNetwork,
    boolean destIsCriticalAsset
) {}
