package com.ids.enums;

public enum Severity {

    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    public static Severity fromString(String value) {
        try {
            return Severity.valueOf(value.toUpperCase());
        } catch (Exception e) {
            return MEDIUM; // safe default
        }
    }
}