package com.ids.desktop.controller;

import javafx.beans.property.SimpleBooleanProperty;

/**
 * One host interface row in the Config tab's checkbox list: device name + first
 * IP, plus a live {@code selected} state that {@code CheckBoxListCell} binds to.
 * Toggling the checkbox mutates {@link #selectedProperty()}; Save reads it back.
 */
public class InterfaceChoice {

    private final String name;
    private final String ip;
    private final SimpleBooleanProperty selected;

    public InterfaceChoice(String name, String ip, boolean selected) {
        this.name     = name;
        this.ip       = ip;
        this.selected = new SimpleBooleanProperty(selected);
    }

    public String getName() { return name; }
    public String getIp()   { return ip; }

    public SimpleBooleanProperty selectedProperty() { return selected; }
    public boolean isSelected() { return selected.get(); }

    /** Text rendered next to the checkbox (CheckBoxListCell default converter). */
    @Override public String toString() {
        return (ip == null || ip.isBlank()) ? name : name + "   (" + ip + ")";
    }
}
