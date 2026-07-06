package com.ids.dto;

import java.time.Instant;

public class AlertGroupDTO {
    private String sourceIp;
    private String sourceMac;
    private Long alertCount;
    private Instant firstSeen;
    private Instant lastSeen;
    private String threatTypes;
    private String severity;
    private boolean hasExistingCase;
    private Long existingCaseId;
    private String existingCaseNumber;

    // getters and setters
    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }
    public String getSourceMac() { return sourceMac; }
    public void setSourceMac(String sourceMac) { this.sourceMac = sourceMac; }
    public Long getAlertCount() { return alertCount; }
    public void setAlertCount(Long alertCount) { this.alertCount = alertCount; }
    public Instant getFirstSeen() { return firstSeen; }
    public void setFirstSeen(Instant firstSeen) { this.firstSeen = firstSeen; }
    public Instant getLastSeen() { return lastSeen; }
    public void setLastSeen(Instant lastSeen) { this.lastSeen = lastSeen; }
    public String getThreatTypes() { return threatTypes; }
    public void setThreatTypes(String threatTypes) { this.threatTypes = threatTypes; }
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
    public boolean isHasExistingCase() { return hasExistingCase; }
    public void setHasExistingCase(boolean hasExistingCase) { this.hasExistingCase = hasExistingCase; }
    public Long getExistingCaseId() { return existingCaseId; }
    public void setExistingCaseId(Long existingCaseId) { this.existingCaseId = existingCaseId; }
    public String getExistingCaseNumber() { return existingCaseNumber; }
    public void setExistingCaseNumber(String existingCaseNumber) { this.existingCaseNumber = existingCaseNumber; }
}