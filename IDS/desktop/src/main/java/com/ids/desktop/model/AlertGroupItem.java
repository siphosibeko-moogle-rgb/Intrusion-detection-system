package com.ids.desktop.model;

import javafx.beans.property.*;

/**
 * JavaFX observable row model for the "Create Cases from Alerts" screen.
 * One row per source IP that has ever triggered an alert.
 *
 * Backed by BackendClient.fetchAlertGroups() -> GET /api/forensics/cases/alert-groups
 * (a single server-side GROUP BY query — see ForensicCaseService.getAlertGroupsForCaseCreation()).
 */
public class AlertGroupItem {

    private final StringProperty sourceIp            = new SimpleStringProperty();
    private final StringProperty sourceMac            = new SimpleStringProperty();
    private final LongProperty   alertCount           = new SimpleLongProperty();
    private final StringProperty firstSeen            = new SimpleStringProperty();
    private final StringProperty lastSeen             = new SimpleStringProperty();
    private final StringProperty threatTypes          = new SimpleStringProperty();
    private final StringProperty severity             = new SimpleStringProperty();
    private final BooleanProperty hasExistingCase     = new SimpleBooleanProperty();
    private final LongProperty   existingCaseId       = new SimpleLongProperty();
    private final StringProperty existingCaseNumber   = new SimpleStringProperty();

    public AlertGroupItem() {}

    public AlertGroupItem(String sourceIp, String sourceMac, long alertCount,
                           String firstSeen, String lastSeen,
                           String threatTypes, String severity,
                           boolean hasExistingCase, long existingCaseId,
                           String existingCaseNumber) {
        this.sourceIp.set(sourceIp);
        this.sourceMac.set(sourceMac);
        this.alertCount.set(alertCount);
        this.firstSeen.set(firstSeen);
        this.lastSeen.set(lastSeen);
        this.threatTypes.set(threatTypes);
        this.severity.set(severity);
        this.hasExistingCase.set(hasExistingCase);
        this.existingCaseId.set(existingCaseId);
        this.existingCaseNumber.set(existingCaseNumber);
    }

    // ── Getters ──────────────────────────────────────────────────────────
    public String getSourceIp()            { return sourceIp.get(); }
    public String getSourceMac()           { return sourceMac.get(); }
    public long getAlertCount()            { return alertCount.get(); }
    public String getFirstSeen()           { return firstSeen.get(); }
    public String getLastSeen()            { return lastSeen.get(); }
    public String getThreatTypes()         { return threatTypes.get(); }
    public String getSeverity()            { return severity.get(); }
    public boolean isHasExistingCase()     { return hasExistingCase.get(); }
    public long getExistingCaseId()        { return existingCaseId.get(); }
    public String getExistingCaseNumber()  { return existingCaseNumber.get(); }

    // ── Properties (needed for PropertyValueFactory-based TableColumns) ───
    public StringProperty sourceIpProperty()           { return sourceIp; }
    public StringProperty sourceMacProperty()          { return sourceMac; }
    public LongProperty alertCountProperty()           { return alertCount; }
    public StringProperty firstSeenProperty()          { return firstSeen; }
    public StringProperty lastSeenProperty()           { return lastSeen; }
    public StringProperty threatTypesProperty()        { return threatTypes; }
    public StringProperty severityProperty()           { return severity; }
    public BooleanProperty hasExistingCaseProperty()   { return hasExistingCase; }
    public LongProperty existingCaseIdProperty()       { return existingCaseId; }
    public StringProperty existingCaseNumberProperty() { return existingCaseNumber; }
}