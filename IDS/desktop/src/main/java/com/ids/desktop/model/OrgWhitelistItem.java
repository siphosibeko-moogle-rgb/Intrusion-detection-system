package com.ids.desktop.model;

import javafx.beans.property.*;

public class OrgWhitelistItem {
    private final LongProperty id = new SimpleLongProperty();
    private final StringProperty ip = new SimpleStringProperty();
    private final StringProperty orgName= new SimpleStringProperty();
    private final StringProperty asn = new SimpleStringProperty();
    private final StringProperty country= new SimpleStringProperty();
    private final IntegerProperty hits= new SimpleIntegerProperty();
    private final BooleanProperty approved = new SimpleBooleanProperty();
    private final StringProperty lastSeen = new SimpleStringProperty();
    private final BooleanProperty selected = new SimpleBooleanProperty(false);

    public OrgWhitelistItem() {}
    public OrgWhitelistItem(long id, String ip, String orgName, 
    		String asn, String country, int hits, boolean approved, String lastSeen) {
			this.id.set(id);       
			this.ip.set(ip);         
			this.orgName.set(orgName);
			this.asn.set(asn);     
			this.country.set(country); 
			this.hits.set(hits);
			this.approved.set(approved); 
			this.lastSeen.set(lastSeen);
}
    
    public long getId() { 
    	return id.get(); }
    public String  getIp(){ 
    	return ip.get(); }
    public String  getOrgName() { 
    	return orgName.get(); }
    public String  getAsn(){ 
    	return asn.get(); }
    public String  getCountry() { 
    	return country.get(); }
    public int     getHits(){
    	return hits.get(); }
    public boolean getApproved(){ 
    	return approved.get(); }
    public String  getLastSeen(){
    	return lastSeen.get(); }
    public boolean isSelected(){
    	return selected.get(); }
    public void setSelected(boolean v) { 
    	selected.set(v); }

    public LongProperty idProperty()  { 
    	return id; }
    public StringProperty ipProperty(){ 
    	return ip; }
    public StringProperty orgNameProperty(){ 
    	return orgName; }
    public StringProperty asnProperty(){
    	return asn; }
    public StringProperty countryProperty(){ 
    	return country; }
    public IntegerProperty hitsProperty(){ 
    	return hits; }
    public BooleanProperty approvedProperty(){
    	return approved; }
    public StringProperty lastSeenProperty() {
    	return lastSeen; }
    public BooleanProperty selectedProperty(){
    	return selected; }
}