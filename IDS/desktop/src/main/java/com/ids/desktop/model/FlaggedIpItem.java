package com.ids.desktop.model;

import javafx.beans.property.*;

/**
 * Represents a flagged IP from UNKNOWN_IP / OUTSIDE_SUBNET alerts.
 * Displayed in the "Flagged IPs" section of the My Whitelist tab.
 */
public class FlaggedIpItem {

    private final LongProperty   alertId   = new SimpleLongProperty();
    private final StringProperty ip        = new SimpleStringProperty();
    private final StringProperty mac       = new SimpleStringProperty();
    private final StringProperty threatType= new SimpleStringProperty();
    private final StringProperty protocol  = new SimpleStringProperty();
    private final IntegerProperty hits     = new SimpleIntegerProperty();
    private final StringProperty lastSeen  = new SimpleStringProperty();
    private final BooleanProperty selected = new SimpleBooleanProperty(false);

    public FlaggedIpItem() {}

    public FlaggedIpItem(long alertId, String ip, String mac,
                         String threatType, String protocol,
                         int hits, String lastSeen) {
        this.alertId.set(alertId);
        this.ip.set(ip);
        this.mac.set(mac);
        this.threatType.set(threatType);
        this.protocol.set(protocol);
        this.hits.set(hits);
        this.lastSeen.set(lastSeen);
    }

    // Properties
    public LongProperty    alertIdProperty()   { return alertId; }
    public StringProperty  ipProperty()        { return ip; }
    public StringProperty  macProperty()       { return mac; }
    public StringProperty  threatTypeProperty(){ return threatType; }
    public StringProperty  protocolProperty()  { return protocol; }
    public IntegerProperty hitsProperty()      { return hits; }
    public StringProperty  lastSeenProperty()  { return lastSeen; }
    public BooleanProperty selectedProperty()  { return selected; }

    // Getters
    public long   getAlertId()    { return alertId.get(); }
    public String getIp()         { return ip.get(); }
    public String getMac()        { return mac.get(); }
    public String getThreatType() { return threatType.get(); }
    public String getProtocol()   { return protocol.get(); }
    public int    getHits()       { return hits.get(); }
    public String getLastSeen()   { return lastSeen.get(); }
    public boolean isSelected()   { return selected.get(); }
    public void setSelected(boolean v) { selected.set(v); }
}