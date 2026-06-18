package com.ids.dto;

import java.time.Instant;

public record AlertSummaryDTO(
    Long    id,
    String  threatType,
    String  severity,
    String  sourceIp,
    String  destIp,
    String  protocol,
    String  requestType,
    String  details,
    int     packetCount,
    long    windowMs,
    Instant timestamp
) {}