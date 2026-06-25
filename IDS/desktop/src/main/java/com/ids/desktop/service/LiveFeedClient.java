package com.ids.desktop.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javafx.application.Platform;

import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;

import java.net.URI;
import java.util.function.Consumer;

/**
 * WebSocket client connecting to the backend's STOMP /topic/alerts feed.
 *
 * WHY RAW WEBSOCKET OVER A FULL STOMP LIBRARY:
 *   A full STOMP library (e.g. stomp-websocket) adds ~2MB of dependencies and
 *   complex lifecycle management.  The backend uses Spring's simple STOMP broker,
 *   which speaks a text-based protocol we can drive with three plain frames:
 *     CONNECT  → handshake
 *     SUBSCRIBE → tell the broker which topic we want
 *     MESSAGE  → what we receive back
 *   For a read-only desktop client this is all we need.
 *
 * THREADING:
 *   onMessage() is called on the WebSocket I/O thread (not the JavaFX thread).
 *   The caller (MainController) must wrap any UI updates in Platform.runLater().
 *   This class does NOT touch the UI — it only parses JSON and calls onAlert.
 */
public class LiveFeedClient extends WebSocketClient {

    private final ObjectMapper      mapper;
    private final Consumer<JsonNode> onAlert;
    private final Runnable           onConnect;
    private final Runnable           onDisconnect;
    private final Runnable onCleared;

    // ─────────────────────────────────────────────────────────────────────────
    // PRIMARY CONSTRUCTOR — use this one
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @param wsUrl        Full WebSocket URL, e.g. ws://localhost:8080/ws/websocket
     * @param onAlert      Called with a parsed JsonNode for every alert received.
     *                     Runs on the WebSocket I/O thread — wrap UI calls in
     *                     Platform.runLater() on the caller side.
     * @param onConnect    Called when the STOMP handshake succeeds.  May be null.
     * @param onDisconnect Called when the connection closes or errors.  May be null.
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
        send("CONNECT\naccept-version:1.2\n\n\0");
        send("SUBSCRIBE\nid:sub-0\ndestination:/topic/alerts\n\n\0");
        // NEW: subscribe to the clear signal
        send("SUBSCRIBE\nid:sub-1\ndestination:/topic/alerts-cleared\n\n\0");
        if (onConnect != null) onConnect.run();
    }
    @Override
    public void onMessage(String message) {
        try {
            int bodyStart = message.indexOf("\n\n");
            if (bodyStart == -1) return;
            String body = message.substring(bodyStart + 2).replace("\0", "").trim();
            if (body.isEmpty() || !body.startsWith("{")) return;

            // Check which topic this came from
            if (message.contains("destination:/topic/alerts-cleared")) {
                if (onCleared != null) Platform.runLater(onCleared);
                return;
            }
            onAlert.accept(mapper.readTree(body));
        } catch (Exception e) {
            System.err.println("[LiveFeedClient] Parse error: " + e.getMessage());
        }
    }

    @Override
    public void onClose(int code, String reason, boolean remote) {
        if (onDisconnect != null) {
            onDisconnect.run();
        }
    }

    @Override
    public void onError(Exception ex) {
        if (onDisconnect != null) {
            onDisconnect.run();
        }
    }
}