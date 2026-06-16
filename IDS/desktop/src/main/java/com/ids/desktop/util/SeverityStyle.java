package com.ids.desktop.util;

/**
 * Maps severity levels to JavaFX CSS colour strings
 */
public class SeverityStyle {

    public static String toStyle(String severity) {
        return switch (severity == null ? "" : severity.toUpperCase()) {
            case "CRITICAL" -> "-fx-text-fill: #ef4444; -fx-font-weight: bold;";
            case "HIGH"     -> "-fx-text-fill: #f97316; -fx-font-weight: bold;";
            case "MEDIUM"   -> "-fx-text-fill: #eab308;";
            case "LOW"      -> "-fx-text-fill: #22c55e;";
            default         -> "-fx-text-fill: #94a3b8;";
        };
    }

    public static String toRowStyle(String severity) {
        return switch (severity == null ? "" : severity.toUpperCase()) {
            case "CRITICAL" -> "-fx-background-color: rgba(239,68,68,0.10);";
            case "HIGH"     -> "-fx-background-color: rgba(249,115,22,0.08);";
            case "MEDIUM"   -> "-fx-background-color: rgba(234,179,8,0.06);";
            default         -> "";
        };
    }

    public static String toBadge(String severity) {
        return switch (severity == null ? "" : severity.toUpperCase()) {
            case "CRITICAL" -> "CRITICAL";
            case "HIGH"     -> "HIGH";
            case "MEDIUM"   -> "MEDIUM";
            case "LOW"      -> "LOW";
            default         -> severity;
        };
    }
}