package com.ids.model;

import java.time.LocalDateTime;
import com.ids.enums.Severity;
import com.ids.enums.ThreatType;

public class ThreatEventEntity {

    private Long id;
    private String sourceIp;
    private String destinationIp;
    private ThreatType threatType;
    private Severity severity;
    private String protocol;
    private Integer packetCount;
    private LocalDateTime timestamp;
    private String details;

    // getters & setters
}