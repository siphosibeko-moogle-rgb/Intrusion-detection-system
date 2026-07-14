package com.ids.desktop.model;

import javafx.beans.property.*;

public class TrustedNetworkItem {
    private final LongProperty    id       = new SimpleLongProperty();
    private final StringProperty  cidr     = new SimpleStringProperty();
    private final StringProperty  provider = new SimpleStringProperty();
    private final StringProperty  category = new SimpleStringProperty();
    private final BooleanProperty enabled  = new SimpleBooleanProperty(true);
    private final BooleanProperty suppressBeaconing = new SimpleBooleanProperty(false);

    public TrustedNetworkItem() {}
    public TrustedNetworkItem(long id, String cidr, String provider,
                              String category, boolean enabled,
                              boolean suppressBeaconing) {
        this.id.set(id);
        this.cidr.set(cidr);
        this.provider.set(provider);
        this.category.set(category);
        this.enabled.set(enabled);
        this.suppressBeaconing.set(suppressBeaconing);
    }

    public long    getId()                { return id.get(); }
    public String  getCidr()              { return cidr.get(); }
    public String  getProvider()          { return provider.get(); }
    public String  getCategory()          { return category.get(); }
    public boolean isEnabled()            { return enabled.get(); }
    public boolean isSuppressBeaconing()  { return suppressBeaconing.get(); }

    public LongProperty    idProperty()                { return id; }
    public StringProperty  cidrProperty()              { return cidr; }
    public StringProperty  providerProperty()          { return provider; }
    public StringProperty  categoryProperty()          { return category; }
    public BooleanProperty enabledProperty()           { return enabled; }
    public BooleanProperty suppressBeaconingProperty() { return suppressBeaconing; }
}
