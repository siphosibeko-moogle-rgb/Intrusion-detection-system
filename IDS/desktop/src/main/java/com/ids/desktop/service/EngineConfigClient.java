package com.ids.desktop.service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * Thin client for the engine's host-local config endpoint
 * ({@code GET/POST 127.0.0.1:9091/engine/config}), used only by the desktop's
 * Config sub-tab to read/write the engine's {@code ids.capture.interfaces}
 * and a fixed set of structured {@code network.*}/{@code capture.mode} keys.
 *
 * <p>Deliberately separate from {@link BackendClient}: that talks to the Spring
 * backend (JWT auth, base URL, 401 silent-retry). This talks to the engine
 * process directly over loopback with none of that. Merging them would couple
 * two unrelated servers. It reuses the desktop's existing OkHttp + Jackson —
 * no new dependencies.
 *
 * <p><b>Loopback only, by design.</b> The engine binds this endpoint to
 * {@code 127.0.0.1} (see {@code EngineConfigServer}) so it can't be driven
 * off-box; the desktop must run on the same machine. The host:port lives here
 * as the single source of truth.
 */
public class EngineConfigClient {

    // Single source of truth for the engine's loopback config endpoint.
    private static final String ENGINE_CONFIG_URL = "http://127.0.0.1:9091/engine/config";

    /** Shown verbatim when the engine endpoint can't be reached (engine not
     *  running, or desktop on a different host than the engine). */
    public static final String UNREACHABLE_MESSAGE =
        "Engine config endpoint not reachable (127.0.0.1:9091). "
        + "This tab only works when the desktop runs on the same machine as the engine.";

    private static final MediaType JSON = MediaType.get("application/json");

    private final OkHttpClient http;
    private final ObjectMapper mapper = new ObjectMapper();

    public EngineConfigClient() {
        // Short timeouts: this is a loopback call. If the engine isn't running
        // we want to fail fast into UNREACHABLE_MESSAGE, not hang the background
        // thread for the default 10s.
        this.http = new OkHttpClient.Builder()
            .connectTimeout(3, TimeUnit.SECONDS)
            .readTimeout(3, TimeUnit.SECONDS)
            .build();
    }

    /** GET the current config + host interfaces. */
    public EngineConfig fetchConfig() throws IOException {
        Request req = new Request.Builder().url(ENGINE_CONFIG_URL).get().build();
        try (Response resp = execute(req)) {
            if (!resp.isSuccessful()) throw new IOException(errorMessage(resp));
            JsonNode root = mapper.readTree(resp.body().string());

            String current = root.path("captureInterfaces").asText("");
            List<EngineConfig.HostInterface> ifaces = new ArrayList<>();
            for (JsonNode n : root.path("hostInterfaces")) {
                String name = n.path("name").asText("");
                String ip   = n.hasNonNull("ip") ? n.path("ip").asText() : null;
                ifaces.add(new EngineConfig.HostInterface(name, ip));
            }

            Map<String, String> settings = new LinkedHashMap<>();
            JsonNode settingsNode = root.path("settings");
            java.util.Iterator<String> fieldNames = settingsNode.fieldNames();
            while (fieldNames.hasNext()) {
                String key = fieldNames.next();
                settings.put(key, settingsNode.path(key).asText(""));
            }

            return new EngineConfig(current, ifaces, settings);
        }
    }

    /**
     * POST a new {@code ids.capture.interfaces} value (comma-joined names; an
     * empty list means auto-discover). Returns {@code restartRequired} from the
     * engine — always true today, but read from the response rather than assumed.
     */
    public boolean saveCaptureInterfaces(List<String> interfaceNames) throws IOException {
        String value = String.join(",", interfaceNames);
        String body  = mapper.writeValueAsString(
            java.util.Map.of("captureInterfaces", value));
        Request req = new Request.Builder()
            .url(ENGINE_CONFIG_URL)
            .post(RequestBody.create(body, JSON))
            .build();
        try (Response resp = execute(req)) {
            if (!resp.isSuccessful()) throw new IOException(errorMessage(resp));
            JsonNode root = mapper.readTree(resp.body().string());
            return root.path("restartRequired").asBoolean(true);
        }
    }

    /**
     * POST new values for the structured settings keys (e.g.
     * {@code network.subnet}, {@code capture.mode}) — a form field of the
     * given key is skipped entirely (map key omitted) rather than sent, so a
     * caller that only fetched/edited a subset can save just that subset.
     * Server-side validation mirrors the engine's own parser; a rejected
     * value throws with the engine's message naming the bad key. Returns
     * {@code restartRequired} from the engine, same as
     * {@link #saveCaptureInterfaces}. Independent of that call — this never
     * touches {@code ids.capture.interfaces}.
     */
    public boolean saveSettings(Map<String, String> settings) throws IOException {
        String body = mapper.writeValueAsString(java.util.Map.of("settings", settings));
        Request req = new Request.Builder()
            .url(ENGINE_CONFIG_URL)
            .post(RequestBody.create(body, JSON))
            .build();
        try (Response resp = execute(req)) {
            if (!resp.isSuccessful()) throw new IOException(errorMessage(resp));
            JsonNode root = mapper.readTree(resp.body().string());
            return root.path("restartRequired").asBoolean(true);
        }
    }

    /** Runs the call, translating connect/timeout failures into the clear,
     *  non-alarming UNREACHABLE_MESSAGE so the UI can show it as-is. */
    private Response execute(Request req) throws IOException {
        try {
            return http.newCall(req).execute();
        } catch (java.net.ConnectException | java.net.SocketTimeoutException
               | java.net.UnknownHostException | java.net.NoRouteToHostException e) {
            throw new IOException(UNREACHABLE_MESSAGE);
        }
    }

    /** Extracts the engine's {"error":"..."} body, falling back to "HTTP <code>". */
    private String errorMessage(Response resp) {
        try {
            String body = resp.body() != null ? resp.body().string() : null;
            if (body != null && !body.isEmpty()) {
                JsonNode err = mapper.readTree(body).get("error");
                if (err != null && !err.asText().isEmpty()) return err.asText();
            }
        } catch (Exception ignored) {
            // fall through
        }
        return "HTTP " + resp.code();
    }
}
