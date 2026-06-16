package com.ids.desktop.model;

import javafx.beans.property.*;

public class MyWhitelistItem {
    private final LongProperty   id = new SimpleLongProperty();
    private final StringProperty ip = new SimpleStringProperty();
    private final StringProperty mac = new SimpleStringProperty();
    private final StringProperty label= new SimpleStringProperty();
    private final StringProperty addedAt= new SimpleStringProperty();

    public MyWhitelistItem() {}
    public MyWhitelistItem(long id, String ip, String mac, String label, String addedAt) {
        this.id.set(id); 
        this.ip.set(ip); 
        this.mac.set(mac);
        this.label.set(label); 
        this.addedAt.set(addedAt);
    }

    public long   getId() { 
    	return id.get(); 
    	}
    public String getIp(){ 
    	return ip.get(); 
    	}
    public String getMac(){ 
    	return mac.get(); }
    public String getLabel(){ 
    	return label.get(); 
    	}
    public String getAddedAt(){
    	return addedAt.get();
    	}

    public LongProperty idProperty(){ 
    	return id; 
    	}
    public StringProperty ipProperty(){ 
    	return ip; 
    	}
    public StringProperty macProperty(){
    	return mac; 
    	}
    public StringProperty labelProperty(){ 
    	return label; 
    	}
    public StringProperty addedAtProperty(){
    	return addedAt;
    	}
}