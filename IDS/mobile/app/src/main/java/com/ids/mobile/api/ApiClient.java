package com.ids.mobile.api;

import com.ids.mobile.model.FlaggedIp;
import com.ids.mobile.model.HealthComponent;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

/**
 * ApiClient — the ONLY class in this app that touches the network.
 *
 * READ-ONLY BY CONSTRUCTION: the only non-GET method here is login(). There is
 * no post/put/patch/delete helper at all. That is deliberate — a mobile glance
 * client that cannot write cannot cause an incident, and the absence of the
 * helper methods makes it impossible to add a write call by accident.
 *
 * THREADING: every method here BLOCKS. Never call one from the main thread;
 * Android will throw NetworkOnMainThreadException. Use Poller, which owns the
 * background thread and marshals results back to the UI thread.
 */
public class ApiClient {

    private static final MediaType JSON = MediaType.get("application/json");

    private final String baseUrl;
    private final OkHttpClient http;

    /** volatile: written by the login thread, read by both poller threads. */
    private volatile String jwt = "";

    public ApiClient(String baseUrl) {
        this.baseUrl = stripTrailingSlash(baseUrl);
        this.http = new OkHttpClient.Builder()
                .connectTimeout(8, TimeUnit.SECONDS)
                .readTimeout(10, TimeUnit.SECONDS)
                .build();
    }

    public String baseUrl()   { return baseUrl; }
    public boolean isLoggedIn() { return !jwt.isEmpty(); }
    public void logout()      { jwt = ""; }

    // ── AUTH ────────────────────────────────────────────────────────────

    /**
     * POST /api/auth/login -> { "token": "..." }
     * Matches the contract the JavaFX BackendClient already relies on.
     */
    public boolean login(String username, String password) throws IOException {
        JSONObject body = new JSONObject();
        try {
            body.put("username", username);
            body.put("password", password);
        } catch (JSONException e) {
            throw new IOException("Could not build login request", e);
        }

        Request req = new Request.Builder()
                .url(baseUrl + "/api/auth/login")
                .post(RequestBody.create(body.toString(), JSON))
                .build();

        try (Response resp = http.newCall(req).execute()) {
            if (!resp.isSuccessful()) return false;
            String raw = bodyString(resp);
            try {
                jwt = new JSONObject(raw).optString("token", "");
            } catch (JSONException e) {
                throw new IOException("Unexpected login response", e);
            }
            return !jwt.isEmpty();
        }
    }

    // ── SYSTEM HEALTH ───────────────────────────────────────────────────

    /**
     * GET /api/dashboard/health
     *
     * The backend returns a flat object whose shape is fixed by
     * DashboardController.health():
     *
     *   backendApi     : { status }
     *   database       : { status }
     *   cpu / ram / disk : { status, value }
     *   cpuUsagePct / ramUsagePct / diskUsagePct : number (-1 when unknown)
     *   packetCapture  : { status, note }
     *   liveFeed       : { status, note }
     *
     * IMPORTANT AND NOT A BUG: packetCapture and liveFeed are NOT a sensor
     * heartbeat. The backend derives them from how long ago the last alert was
     * ingested (OK < 5min, WARN < 30min, else ERROR). A genuinely quiet network
     * is therefore indistinguishable from a dead capture engine. We surface that
     * caveat in the UI rather than letting a green dot imply more than it means.
     */
    public List<HealthComponent> fetchHealth() throws IOException {
        JSONObject o;
        try {
            o = new JSONObject(get("/api/dashboard/health"));
        } catch (JSONException e) {
            throw new IOException("Malformed health response", e);
        }

        List<HealthComponent> out = new ArrayList<>();

        // Capture-path first: it is the reason this screen exists.
        out.add(nested(o, "packetCapture", "Packet Capture"));
        out.add(nested(o, "liveFeed", "Live Feed"));
        out.add(nested(o, "backendApi", "Backend API"));
        out.add(nested(o, "database", "Database"));
        out.add(metric(o, "cpu", "cpuUsagePct", "CPU"));
        out.add(metric(o, "ram", "ramUsagePct", "Memory"));
        out.add(metric(o, "disk", "diskUsagePct", "Disk"));

        return out;
    }

    /** Reads { status, note } style entries. */
    private HealthComponent nested(JSONObject root, String key, String label) {
        JSONObject n = root.optJSONObject(key);
        if (n == null) return new HealthComponent(label, "UNKNOWN", "not reported");
        String status = n.optString("status", "UNKNOWN");
        String note = n.optString("note", "");
        return new HealthComponent(label, status, note);
    }

    /** Reads { status, value } entries, preferring the top-level *UsagePct field. */
    private HealthComponent metric(JSONObject root, String key, String pctKey, String label) {
        JSONObject n = root.optJSONObject(key);
        String status = (n == null) ? "UNKNOWN" : n.optString("status", "UNKNOWN");

        double pct = root.optDouble(pctKey, -1);
        if (pct < 0 && n != null) pct = n.optDouble("value", -1);

        // The backend uses -1 as its explicit "could not measure" sentinel
        // (restricted MXBean inside some containers). Do not render -1%.
        String detail = (pct < 0) ? "unavailable" : String.format("%.1f%% used", pct);
        return new HealthComponent(label, status, detail);
    }

    // ── THREAT ACTORS / TOP SOURCE IPs ──────────────────────────────────

    /**
     * GET /api/alerts/flagged-ips
     *
     * Field names match exactly what the desktop BackendClient.fetchFlaggedIps()
     * reads, so both clients stay on one contract.
     *
     * Chosen over /api/dashboard/threat-actors on purpose: that endpoint still
     * carries the known N+1 query, and a phone polling it every 10s would make a
     * server-side problem worse. flagged-ips gives the same "who is hitting us"
     * answer without that cost.
     */
    public List<FlaggedIp> fetchFlaggedIps() throws IOException {
        JSONArray arr;
        try {
            arr = new JSONArray(get("/api/alerts/flagged-ips"));
        } catch (JSONException e) {
            throw new IOException("Malformed flagged-ips response", e);
        }

        List<FlaggedIp> list = new ArrayList<>(arr.length());
        for (int i = 0; i < arr.length(); i++) {
            JSONObject n = arr.optJSONObject(i);
            if (n == null) continue;
            list.add(new FlaggedIp(
                    n.optString("ip", ""),
                    n.optString("mac", ""),
                    n.optString("organization", "Unknown"),
                    n.optString("asn", ""),
                    n.optString("country", ""),
                    n.optString("threatType", ""),
                    n.optString("protocol", ""),
                    n.optString("severity", ""),
                    n.optInt("hits", 0),
                    n.optString("lastSeen", "")
            ));
        }

        // Sort client-side: the endpoint makes no ordering guarantee, and a
        // glance screen is worthless if the loudest actor is not on top.
        Collections.sort(list, (a, b) -> Integer.compare(b.hits, a.hits));
        return list;
    }

    // ── HTTP PLUMBING ───────────────────────────────────────────────────

    private String get(String path) throws IOException {
        Request req = new Request.Builder()
                .url(baseUrl + path)
                .addHeader("Authorization", "Bearer " + jwt)
                .get()
                .build();

        try (Response resp = http.newCall(req).execute()) {
            if (resp.code() == 401 || resp.code() == 403) {
                jwt = "";                       // stop re-sending a token we know is dead
                throw new AuthExpiredException();
            }
            if (!resp.isSuccessful()) {
                throw new IOException("HTTP " + resp.code());
            }
            return bodyString(resp);
        }
    }

    private static String bodyString(Response resp) throws IOException {
        ResponseBody b = resp.body();
        return b == null ? "" : b.string();
    }

    private static String stripTrailingSlash(String url) {
        String u = url == null ? "" : url.trim();
        while (u.endsWith("/")) u = u.substring(0, u.length() - 1);
        return u;
    }
}
