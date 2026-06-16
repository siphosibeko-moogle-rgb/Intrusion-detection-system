package com.ids.desktop.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
                          Runnable onDisconnect) throws Exception {
        super(new URI(wsUrl));
        this.onAlert      = onAlert;
        this.onConnect    = onConnect;
        this.onDisconnect = onDisconnect;
        this.mapper       = new ObjectMapper();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CONVENIENCE CONSTRUCTOR — used by MainController (no connect/disconnect hooks)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Simplified constructor when you only care about receiving alerts.
     * The token parameter is accepted for API symmetry but is not used in the
     * WebSocket handshake here — the backend's WebSocket endpoint is permit-all
     * in SecurityConfig (STOMP auth is handled separately if needed).
     *
     * WHY the old stub was broken:
     *   The previous stub had signature (String wsUrl, Consumer<JsonNode> token, Object object).
     *   The second parameter was typed as Consumer<JsonNode> but named "token" — it was
     *   the onAlert callback being silently discarded.  This constructor fixes the
     *   parameter order and properly delegates to the primary constructor.
     */
    public LiveFeedClient(String wsUrl,
                          String token,
                          Consumer<JsonNode> onAlert) throws Exception {
        this(wsUrl, onAlert, null, null);
        // token is intentionally unused here; the /ws endpoint is permit-all.
        // If you later add STOMP-level auth, pass token in the CONNECT frame headers.
    }

    // ─────────────────────────────────────────────────────────────────────────
    // WEBSOCKET LIFECYCLE
    // ─────────────────────────────────────────────────────────────────────────

    @Override
    public void onOpen(ServerHandshake hs) {
        // STOMP CONNECT frame — required handshake before subscribing.
        // accept-version:1.2 tells the broker we support STOMP 1.2.
        send("CONNECT\naccept-version:1.2\n\n\0");

        // STOMP SUBSCRIBE frame — tell the broker which topic we want.
        // id:sub-0 is just a client-side subscription identifier.
        send("SUBSCRIBE\nid:sub-0\ndestination:/topic/alerts\n\n\0");

        // Null-safe: onConnect may be null if the convenience constructor was used.
        if (onConnect != null) {
            onConnect.run();
        }
    }

    @Override
    public void onMessage(String message) {
        // STOMP MESSAGE frames look like:
        //   MESSAGE
        //   destination:/topic/alerts
        //   content-type:application/json
        //
        //   {"severity":"HIGH","threatType":"SYN_FLOOD",...}\0
        //
        // We strip the headers by finding the blank line (\n\n) and taking
        // everything after it, then remove the STOMP null terminator (\0).

        try {
            int bodyStart = message.indexOf("\n\n");
            if (bodyStart == -1) return;   // not a MESSAGE frame (e.g. CONNECTED)

            String body = message.substring(bodyStart + 2)
                                 .replace("\0", "")
                                 .trim();

            if (body.isEmpty() || !body.startsWith("{")) return;

            JsonNode node = mapper.readTree(body);

            // onAlert is guaranteed non-null (set in primary constructor).
            onAlert.accept(node);

        } catch (Exception ignored) {
            // Malformed JSON from the broker — swallow silently.
            // In production you would log this to a metrics counter.
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
        // onError is always followed by onClose in java-websocket,
        // so we only need to fire the disconnect callback here if onClose
        // won't be called (it always is, so this is just defensive).
        if (onDisconnect != null) {
            onDisconnect.run();
        }
    }
}