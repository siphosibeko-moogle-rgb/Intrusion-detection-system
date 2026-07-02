package com.ids.desktop.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javafx.application.Platform;

import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;

import java.net.URI;
import java.util.function.Consumer;

/**
 * WebSocket client connecting to the backend's STOMP broker.
 *
 * Subscribed topics:
 *   /topic/alerts          — new and updated AlertSummary payloads
 *   /topic/alerts/deleted  — deletion events {"id": X} when a row is dismissed
 *   /topic/alerts-cleared  — bulk clear signal (triggers onCleared callback)
 *
 * WHY RAW WEBSOCKET:
 *   A full STOMP library (~2MB) adds complexity for what we need:
 *   CONNECT → SUBSCRIBE → handle MESSAGE frames.
 *   The backend uses Spring's simple STOMP broker, which speaks plain text
 *   frames we can drive ourselves.
 *
 * THREADING:
 *   onMessage() runs on the WebSocket I/O thread — NOT the JavaFX thread.
 *   All UI mutations must go through Platform.runLater() on the caller side.
 *   This class does NOT touch the UI. It parses JSON and calls the callbacks.
 */
public class LiveFeedClient extends WebSocketClient {

    private final ObjectMapper      mapper;
    private final Consumer<JsonNode> onAlert;      // handles alerts AND deletion events
    private final Runnable           onConnect;
    private final Runnable           onDisconnect;
    private final Runnable           onCleared;    // optional bulk-clear handler

    /**
     * @param wsUrl        Full WebSocket URL, e.g. ws://localhost:8080/ws/websocket
     * @param onAlert      Called with the parsed JsonNode for:
     *                       - every AlertSummary pushed on /topic/alerts
     *                       - every deletion event {"id":X} on /topic/alerts/deleted
     *                     Caller distinguishes them by checking node.has("threatType").
     *                     Runs on the WS I/O thread — wrap UI calls in Platform.runLater().
     * @param onConnect    Called when the STOMP handshake completes. May be null.
     * @param onDisconnect Called when the connection closes or errors. May be null.
     * @param onCleared    Called (via Platform.runLater) when /topic/alerts-cleared fires.
     *                     May be null if bulk-clear is handled locally.
     */
    public LiveFeedClient(String wsUrl,
                          Consumer<JsonNode> onAlert,
                          Runnable onConnect,
                          Runnable onDisconnect,
                          Runnable onCleared) throws Exception {
        super(new URI(wsUrl));
        this.onAlert      = onAlert;
        this.onConnect    = onConnect;
        this.onDisconnect = onDisconnect;
        this.onCleared    = onCleared;
        this.mapper       = new ObjectMapper();
    }

    @Override
    public void onOpen(ServerHandshake hs) {
        // STOMP CONNECT frame
        send("CONNECT\naccept-version:1.2\n\n\0");

        // Subscribe to new/updated alert summaries
        send("SUBSCRIBE\nid:sub-0\ndestination:/topic/alerts\n\n\0");

        // FIX: Subscribe to per-row deletion events.
        // Backend broadcasts {"id": X} here after DELETE /api/alerts/summaries/{id}.
        // These messages fall through the onCleared check in onMessage() and are
        // delivered to onAlert, where MainController.onAlertReceived() routes them
        // to alertManager.removeById(id) based on the absence of "threatType".
        send("SUBSCRIBE\nid:sub-1\ndestination:/topic/alerts/deleted\n\n\0");

        // Subscribe to bulk-clear signal
        send("SUBSCRIBE\nid:sub-2\ndestination:/topic/alerts-cleared\n\n\0");

        if (onConnect != null) onConnect.run();
    }

    @Override
    public void onMessage(String message) {
        try {
            // Extract the JSON body — it follows the blank line after the STOMP headers
            int bodyStart = message.indexOf("\n\n");
            if (bodyStart == -1) return;
            String body = message.substring(bodyStart + 2).replace("\0", "").trim();
            if (body.isEmpty() || !body.startsWith("{")) return;

            // Route bulk-clear to its own callback (if provided)
            if (message.contains("destination:/topic/alerts-cleared")) {
                if (onCleared != null) Platform.runLater(onCleared);
                return;
            }

            // Everything else — both /topic/alerts and /topic/alerts/deleted —
            // goes to onAlert.  MainController.onAlertReceived() distinguishes:
            //   - deletion payload:  has "id", lacks "threatType"
            //   - alert payload:     has both "id" and "threatType"
            if (onAlert != null) onAlert.accept(mapper.readTree(body));

        } catch (Exception e) {
            System.err.println("[LiveFeedClient] Parse error: " + e.getMessage());
        }
    }

    @Override
    public void onClose(int code, String reason, boolean remote) {
        if (onDisconnect != null) onDisconnect.run();
    }

    @Override
    public void onError(Exception ex) {
        System.err.println("[LiveFeedClient] Error: " + ex.getMessage());
        if (onDisconnect != null) onDisconnect.run();
    }
}