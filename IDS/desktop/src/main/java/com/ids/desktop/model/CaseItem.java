package com.ids.desktop.model;

import javafx.beans.property.SimpleLongProperty;
import javafx.beans.property.SimpleStringProperty;

/**
 * JavaFX observable model for a forensic case row in the TableView.
 */
public class CaseItem {

    private final SimpleLongProperty id= new SimpleLongProperty();
    private final SimpleStringProperty caseNumber = new SimpleStringProperty();
    private final SimpleStringProperty title= new SimpleStringProperty();
    private final SimpleStringProperty status= new SimpleStringProperty();
    private final SimpleStringProperty severity= new SimpleStringProperty();
    private final SimpleStringProperty suspectIp= new SimpleStringProperty();
    private final SimpleStringProperty suspectMac = new SimpleStringProperty();
    private final SimpleStringProperty threatType= new SimpleStringProperty();
    private final SimpleStringProperty assignedTo= new SimpleStringProperty();
    private final SimpleStringProperty openedAt= new SimpleStringProperty();
    private final SimpleStringProperty findings= new SimpleStringProperty();

    public CaseItem() {}

    public CaseItem(long id, String caseNumber, String title, String status,
                    String severity, String suspectIp, String suspectMac,
                    String threatType, String assignedTo,
                    String openedAt, String findings) {
        this.id.set(id);
        this.caseNumber.set(caseNumber);
        this.title.set(title);
        this.status.set(status);
        this.severity.set(severity);
        this.suspectIp.set(suspectIp);
        this.suspectMac.set(suspectMac);
        this.threatType.set(threatType);
        this.assignedTo.set(assignedTo);
        this.openedAt.set(openedAt);
        this.findings.set(findings);
    }

    public SimpleLongProperty idProperty(){ 
    	return id; }
    public SimpleStringProperty caseNumberProperty() { 
    	return caseNumber; }
    public SimpleStringProperty titleProperty(){ 
    	return title; 
    	}
    public SimpleStringProperty statusProperty(){ 
    	return status; 
    	}
    public SimpleStringProperty severityProperty(){ 
    	return severity; 
    	}
    public SimpleStringProperty suspectIpProperty(){ 
    	return suspectIp; }
    public SimpleStringProperty suspectMacProperty(){ 
    	return suspectMac; }
    public SimpleStringProperty threatTypeProperty(){ 
    	return threatType; }
    public SimpleStringProperty assignedToProperty(){ 
    	return assignedTo; }
    public SimpleStringProperty openedAtProperty(){ 
    	return openedAt; }
    public SimpleStringProperty findingsProperty(){ 
    	return findings; }

    public long   getId(){
    	return id.get(); }
    public String getCaseNumber(){
    	return caseNumber.get(); }
    public String getTitle(){ 
    	return title.get(); 
    	}
    public String getStatus(){ 
    	return status.get(); }
    public String getSeverity(){ 
    	return severity.get(); }
    public String getSuspectIp(){
    	return suspectIp.get(); }
    public String getSuspectMac(){
    	return suspectMac.get(); }
    public String getThreatType(){ 
    	return threatType.get(); }
    public String getAssignedTo() { 
    	return assignedTo.get(); }
    public String getOpenedAt()   { 
    	return openedAt.get(); }
    public String getFindings()   { 
    	return findings.get(); }
}