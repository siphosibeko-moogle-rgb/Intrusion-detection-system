package com.ids.enums;


public enum ThreatType {

    ARP_SPOOFING,
    DNS_TUNNELING,
    PORT_SCAN,
    UNKNOWN;

    public static ThreatType fromString(String value) {
        try {
            return ThreatType.valueOf(value.toUpperCase());
        } catch (Exception e) {
            return UNKNOWN;
        }
    }
}