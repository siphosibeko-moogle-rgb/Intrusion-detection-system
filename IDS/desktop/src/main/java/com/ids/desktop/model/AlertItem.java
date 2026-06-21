package com.ids.desktop.model;

import javafx.beans.property.SimpleIntegerProperty;
import javafx.beans.property.SimpleStringProperty;

/**
 * JavaFX observable model for a single alert row in the TableView.
 */
public class AlertItem {

    private final SimpleStringProperty timestamp= new SimpleStringProperty();
    private final SimpleStringProperty severity= new SimpleStringProperty();
    private final SimpleStringProperty threatType= new SimpleStringProperty();
    private final SimpleStringProperty sourceIp= new SimpleStringProperty();
    private final SimpleStringProperty sourceMac= new SimpleStringProperty();
    private final SimpleStringProperty destIp= new SimpleStringProperty();
    private final SimpleStringProperty protocol= new SimpleStringProperty();
    private final SimpleStringProperty requestType= new SimpleStringProperty();
    private final SimpleIntegerProperty packetCount= new SimpleIntegerProperty();
    private final SimpleStringProperty details= new SimpleStringProperty();
    private final SimpleIntegerProperty occurrences = new SimpleIntegerProperty(1);
    private final SimpleStringProperty  firstSeen    = new SimpleStringProperty();

    public AlertItem() {}

    public AlertItem(String timestamp, String severity, String threatType,
                     String sourceIp, String sourceMac, String destIp,
                     String protocol, String requestType, int packetCount, String details) {
        this.timestamp.set(timestamp);
        this.severity.set(severity);
        this.threatType.set(threatType);
        this.sourceIp.set(sourceIp);
        this.sourceMac.set(sourceMac);
        this.destIp.set(destIp);
        this.protocol.set(protocol);
        this.requestType.set(requestType);
        this.packetCount.set(packetCount);
        this.details.set(details);
    }
    public SimpleIntegerProperty occurrencesProperty() { 
    	return occurrences; }
    public SimpleStringProperty  firstSeenProperty()   { 
    	return firstSeen; }
    public SimpleStringProperty timestampProperty(){ 
    	return timestamp;
    	}
    public SimpleStringProperty severityProperty(){ 
    	return severity; 
    	}
    public SimpleStringProperty threatTypeProperty() { 
    	return threatType; 
    	}
    public SimpleStringProperty sourceIpProperty() { 
    	return sourceIp; 
    	}
    public SimpleStringProperty sourceMacProperty() { 
    	return sourceMac; 
    	}
    public SimpleStringProperty destIpProperty() { 
    	return destIp; 
    	}
    public SimpleStringProperty protocolProperty() { 
    	return protocol; 
    	}
    public SimpleStringProperty requestTypeProperty() {
    	return requestType;
    	}
    public SimpleIntegerProperty packetCountProperty() { 
    	return packetCount; 
    	}
    public SimpleStringProperty detailsProperty() { 
    	return details;
    	}

    public String getTimestamp(){ 
    	return timestamp.get(); 
    	}
    public String getSeverity(){ 
    	return severity.get();
    	}
    public String getThreatType(){ 
    	return threatType.get(); 
    	}
    public String getSourceIp(){ 
    	return sourceIp.get(); 
    	}
    public String getSourceMac(){ 
    	return sourceMac.get(); 
    	}
    public String getDestIp(){ 
    	return destIp.get(); 
    	}
    public String getProtocol() { 
    	return protocol.get();
    	}
    public String getRequestType() { 
    	return requestType.get(); 
    	}
    public int    getPacketCount() {
    	return packetCount.get();
    	}
    public String getDetails(){ 
    	return details.get(); 
    	}
    public int    getOccurrences() { 
    	return occurrences.get(); }
    public String getFirstSeen()   { 
    	return firstSeen.get(); }
    public void   setOccurrences(int v) { 
    	occurrences.set(v); }
    public void   setFirstSeen(String v) { 
    	firstSeen.set(v); }
    public void   setTimestamp(String v) { 
    	timestamp.set(v); }
}