package com.ids.repository;

import java.time.Instant;

public interface AlertGroupProjection {
    String getSourceIp();
    String getSourceMac();
    Long getAlertCount();
    Instant getFirstSeen();
    Instant getLastSeen();
    String getThreatTypes();
    Integer getSeverityRank();
}