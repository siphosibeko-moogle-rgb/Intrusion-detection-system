package com.ids.desktop.controller;

import com.fasterxml.jackson.databind.JsonNode;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Tooltip;
import javafx.scene.layout.HBox;
import javafx.scene.paint.Color;
import javafx.scene.shape.Circle;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * HeaderHealthWidget — compact 4-dot system health strip for the top bar.
 *
 * Replaces the old "● Connected" label. Each dot is a Tooltip-labelled
 * Circle; hovering shows the full status name. Data comes from the shared
 * HealthPoller (see MainController wiring) — this widget does NOT poll
 * itself, it just renders whatever JsonNode it's handed via update().
 *
 * NOTE ON SCOPE: the backend health payload has no distinct "engine
 * liveness" signal separate from packet capture, so this widget shows 4
 * real, independently-meaningful dots (Backend, Database, Packet Capture,
 * Live Feed) rather than inventing a 5th that would just duplicate one of
 * the other four under a different name.
 */
public class HeaderHealthWidget extends HBox {

    private static final String COLOR_OK      = "#22c55e";
    private static final String COLOR_WARN    = "#f59e0b";
    private static final String COLOR_ERROR   = "#ef4444";
    private static final String COLOR_UNKNOWN = "#9ca3af";

    private final Map<String, Circle> dots = new LinkedHashMap<>();
    private final Map<String, Tooltip> tooltips = new LinkedHashMap<>();

    public HeaderHealthWidget() {
        setSpacing(10);
        setAlignment(Pos.CENTER_RIGHT);
        setPadding(new Insets(0, 8, 0, 8));

        addDot("backendApi", "Backend API");
        addDot("database", "Database");
        addDot("packetCapture", "Packet Capture");
        addDot("liveFeed", "Live Feed");
    }

    private void addDot(String key, String label) {
        Circle dot = new Circle(5, Color.web(COLOR_UNKNOWN));
        Tooltip tip = new Tooltip(label + ": Unknown");
        Tooltip.install(dot, tip);
        dots.put(key, dot);
        tooltips.put(key, tip);
        getChildren().add(dot);
    }

    /** Call with the JsonNode from GET /api/dashboard/health. Must run on the FX thread. */
    public void update(JsonNode health) {
        if (health == null) return;
        for (Map.Entry<String, Circle> e : dots.entrySet()) {
            String key = e.getKey();
            String status = health.path(key).path("status").asText("UNKNOWN");
            e.getValue().setFill(Color.web(colorFor(status)));
            Tooltip t = tooltips.get(key);
            if (t != null) t.setText(labelFor(key) + ": " + status);
        }
    }

    private String labelFor(String key) {
        return switch (key) {
            case "backendApi" -> "Backend API";
            case "database" -> "Database";
            case "packetCapture" -> "Packet Capture";
            case "liveFeed" -> "Live Feed";
            default -> key;
        };
    }

    private String colorFor(String status) {
        return switch (status.toUpperCase()) {
            case "OK" -> COLOR_OK;
            case "WARN" -> COLOR_WARN;
            case "ERROR" -> COLOR_ERROR;
            default -> COLOR_UNKNOWN;
        };
    }
}