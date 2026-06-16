package com.ids.dto;

import java.util.Map;

public class ThreatEventDTO {

    private String sourceIp;
    private String destinationIp;
    private String threatType;
    private String severity;
    private String protocol;
    private Integer packetCount;
    private String timestamp;
    private Map<String, Object> extraData;

    // ✅ REQUIRED getters
    public String getSourceIp() { return sourceIp; }
    public String getDestinationIp() { return destinationIp; }
    public String getThreatType() { return threatType; }
    public String getSeverity() { return severity; }
    public String getProtocol() { return protocol; }
    public Integer getPacketCount() { return packetCount; }
    public String getTimestamp() { return timestamp; }
    public Map<String, Object> getExtraData() { return extraData; }
}