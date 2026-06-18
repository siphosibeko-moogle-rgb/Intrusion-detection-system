package com.ids.dto;

import java.time.Instant;
import java.util.List;

public record IpProfileDTO(
    String   ip,
    String   mac,
    long     totalAlerts,
    long     targetCount,
    Instant  firstSeen,
    Instant  lastSeen,
    String   topThreatType,
    String   mostTargetedHost,
    int      threatScore,
    String   riskLevel,
    List<String>           protocols,
    List<AlertSummaryDTO>  recentThreats
) {}