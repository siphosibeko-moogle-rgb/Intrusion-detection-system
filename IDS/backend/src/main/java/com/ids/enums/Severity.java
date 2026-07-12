package com.ids.enums;

public enum Severity {

    // Keep in sync with the engine's ThreatEvent.Severity — ordinal order
    // matters there (floor clamping) and alphabetic name matching matters
    // here (fromString / EnumType.STRING persistence).
    INFO,
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