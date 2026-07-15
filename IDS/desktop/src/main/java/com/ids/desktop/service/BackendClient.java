package com.ids.desktop.service;

import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.desktop.model.AlertGroupItem;
import com.ids.desktop.model.AlertItem;
import com.ids.desktop.model.CaseItem;
import com.ids.desktop.model.FlaggedIpItem;
import com.ids.desktop.model.MyWhitelistItem;
import com.ids.desktop.model.TrustedNetworkItem;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class BackendClient {

    private static final DateTimeFormatter FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                         .withZone(ZoneId.systemDefault());


    private final String baseUrl;
    private final OkHttpClient http;
    private final ObjectMapper mapper = new ObjectMapper();
    // volatile: read by FX thread, pollers and WS-driven handlers while silentReLogin() rewrites it
    private volatile String jwtToken = "";

    public void invalidateSession() {
        jwtToken = "";
        username = null;
        password = null;
    }

    public BackendClient(String baseUrl) {
        this.baseUrl = baseUrl;
        this.http = new OkHttpClient.Builder()
            .connectTimeout(8, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .build();
    }

    // ── AUTH ──────────────────────────────────────────────────────────────

    public boolean login(String username, String password) throws IOException {
        String body = mapper.writeValueAsString(
            Map.of("username", username, "password", password));
        Request req = new Request.Builder()
            .url(baseUrl + "/api/auth/login")
            .post(RequestBody.create(body, MediaType.get("application/json")))
            .build();
        try (Response resp = http.newCall(req).execute()) {
            if (!resp.isSuccessful()) return false;
            JsonNode node = mapper.readTree(resp.body().string());
            jwtToken = textOf(node, "token", "");
            if (!jwtToken.isEmpty()) {
                this.username = username;
                this.password = password;
            }
            return !jwtToken.isEmpty();
        }
    }

    public boolean isLoggedIn() { return !jwtToken.isEmpty(); }
    public String getBaseUrl() { return baseUrl; }

    /** Username of the last successful login, or null if never logged in. */
    public String getUsername() { return username; }

    // ── CASE DETAIL PANEL SUPPORT ────────────────────────────────────────────
    // CaseDetailPanel.java (com.ids.desktop.controller) needs raw GET/POST/PUT/
    // DELETE access with the JSON body already serialized by the caller (unlike
    // the typed methods above, which build their own bodies). These are thin
    // public wrappers around the existing private helpers — NOT a general-purpose
    // HTTP client. Keep call sites limited to CaseDetailPanel; if another class
    // needs backend access, add a typed method next to the other typed methods
    // instead of reaching for these.

    /** Raw GET, returns the response body as a JSON string. */
    public String getRaw(String path) throws IOException {
        return get(path);
    }

    /** Raw POST with a pre-serialized JSON body. */
    public void postJson(String path, String json) throws IOException {
        post(path, json);
    }

    // put(...) and delete(...) below are now public — CaseDetailPanel calls
    // them directly for case updates and note deletion.


    // ── ALERTS ────────────────────────────────────────────────────────────

    public List<AlertItem> fetchAlerts() throws IOException {
        return fetchAlerts("/api/alerts");
    }
    public List<AlertItem> fetchBySeverity(String sev) throws IOException {
        return fetchAlerts("/api/alerts?severity=" + sev);
    }
    public List<AlertItem> fetchByType(String type) throws IOException {
        return fetchAlerts("/api/alerts?type=" + encode(type));
    }
    public List<AlertItem> fetchBySourceIp(String ip) throws IOException {
        return fetchAlerts("/api/alerts?sourceIp=" + ip);
    }
    public List<AlertItem> fetchBySourceMac(String mac) throws IOException {
        return fetchAlerts("/api/alerts?sourceMac=" + encode(mac));
    }
    public List<AlertItem> fetchSince(long epochMs) throws IOException {
        return fetchAlerts("/api/alerts?sinceMs=" + epochMs);
    }

    private List<AlertItem> fetchAlerts(String path) throws IOException {
        List<AlertItem> list = new ArrayList<>();
        for (JsonNode n : mapper.readTree(get(path))) {
            list.add(new AlertItem(
                formatTs(textOf(n, "timestamp", "")),
                textOf(n, "severity", ""),
                textOf(n, "threatType", ""),
                textOf(n, "sourceIp", ""),
                textOf(n, "sourceMac", ""),
                textOf(n, "destIp", ""),
                textOf(n, "protocol", ""),
                textOf(n, "requestType", ""),
                intOf(n, "packetCount", 0),
                textOf(n, "details", "")
            ));
        }
        return list;
    }

    /**
     * Fetches deduplicated AlertSummary rows — what the dashboard actually displays.
     *
     * FIX: Now maps the `id` field from each summary row into AlertItem.id.
     * Without this, the desktop had no way to call DELETE /api/alerts/summaries/{id}.
     */
    public List<AlertItem> fetchAlertSummaries() throws IOException {
        List<AlertItem> list = new ArrayList<>();
        for (JsonNode n : mapper.readTree(get("/api/alerts/summary"))) {
            AlertItem item = new AlertItem(
                formatTs(textOf(n, "lastSeen", "")),
                textOf(n, "severity", ""),
                textOf(n, "threatType", ""),
                textOf(n, "sourceIp", ""),
                textOf(n, "sourceMac", ""),
                textOf(n, "destIp", ""),
                textOf(n, "protocol", ""),
                textOf(n, "requestType", ""),
                intOf(n, "packetCount", 0),
                textOf(n, "details", "")
            );
            // FIX: map the summary row's database id so delete works
            item.setId(longOf(n, "id", 0L));
            item.setOccurrences(intOf(n, "occurrenceCount", 1));
            item.setFirstSeen(formatTs(textOf(n, "firstSeen", "")));
            list.add(item);
        }
        return list;
    }

    public JsonNode fetchStats() throws IOException {
        return mapper.readTree(get("/api/alerts/stats"));
    }

    /**
     * Deletes a single AlertSummary row by its id.
     * Calls DELETE /api/alerts/summaries/{id}.
     *
     * FIX: This is the correct delete method. Previously only DELETE /api/alerts
     * (clear-all) existed. The desktop now calls this per-row so individual
     * alerts can be dismissed without wiping the entire table.
     */
    public void deleteAlertSummary(long id) throws IOException {
        delete("/api/alerts/summaries/" + id);
    }

    /**
     * Clears ALL alert summaries and raw alerts.
     * Calls DELETE /api/alerts.
     */
    public void clearAlerts() throws IOException {
        Request req = new Request.Builder()
            .url(baseUrl + "/api/alerts")
            .header("Authorization", "Bearer " + jwtToken)
            .delete()
            .build();
        try (Response resp = http.newCall(req).execute()) {
            if (!resp.isSuccessful())
                throw new IOException("Clear failed: " + resp.code());
        }
    }

    // ── MY WHITELIST ──────────────────────────────────────────────────────

    public List<MyWhitelistItem> fetchMyWhitelist() throws IOException {
        List<MyWhitelistItem> list = new ArrayList<>();
        for (JsonNode n : mapper.readTree(get("/api/my-whitelist"))) {
            list.add(new MyWhitelistItem(
                longOf(n, "id", 0L),
                textOf(n, "ip", ""),
                textOf(n, "mac", ""),
                textOf(n, "label", ""),
                formatTs(textOf(n, "addedAt", ""))
            ));
        }
        return list;
    }

    public void addMyWhitelistEntry(String ip, String mac, String label) throws IOException {
        String body = mapper.writeValueAsString(
            Map.of("ip", ip, "mac", mac, "label", label));
        post("/api/my-whitelist", body);
    }

    public void deleteMyWhitelistEntry(long id) throws IOException {
        delete("/api/my-whitelist/" + id);
    }

    // ── TRUSTED NETWORKS (provider CIDR ranges) ───────────────────────────

    public List<TrustedNetworkItem> fetchTrustedNetworks() throws IOException {
        List<TrustedNetworkItem> list = new ArrayList<>();
        for (JsonNode n : mapper.readTree(get("/api/trusted-networks"))) {
            list.add(new TrustedNetworkItem(
                longOf(n, "id", 0L),
                textOf(n, "cidr", ""),
                textOf(n, "provider", ""),
                textOf(n, "category", ""),
                boolOf(n, "enabled", true),
                boolOf(n, "suppressBeaconing", false)
            ));
        }
        return list;
    }

    public void addTrustedNetwork(String cidr, String provider, String category,
                                  boolean suppressBeaconing) throws IOException {
        String body = mapper.writeValueAsString(Map.of(
            "cidr", cidr,
            "provider", provider,
            "category", category,
            "suppressBeaconing", suppressBeaconing));
        post("/api/trusted-networks", body);
    }

    public void setTrustedNetworkEnabled(long id, boolean enabled) throws IOException {
        patchJson("/api/trusted-networks/" + id,
            mapper.writeValueAsString(Map.of("enabled", enabled)));
    }

    public void deleteTrustedNetwork(long id) throws IOException {
        delete("/api/trusted-networks/" + id);
    }

    /**
     * Triggers the backend's provider-feed sync and returns a one-line
     * per-provider summary ("Cloudflare: added 2, … | AWS: FAILED: …").
     *
     * Uses a long-read-timeout clone of the shared client: the backend
     * fetches four external feeds serially (the Azure one via a two-step
     * page scrape), which routinely takes longer than the default 10s
     * read timeout.
     */
    public String syncTrustedNetworkFeeds() throws IOException {
        OkHttpClient longHttp = http.newBuilder()
            .readTimeout(120, TimeUnit.SECONDS)
            .build();
        Request req = new Request.Builder()
            .url(baseUrl + "/api/trusted-networks/sync")
            .addHeader("Authorization", "Bearer " + jwtToken)
            .post(RequestBody.create("{}", MediaType.get("application/json")))
            .build();
        try (Response resp = longHttp.newCall(req).execute()) {
            if (!resp.isSuccessful()) throw new IOException("HTTP " + resp.code());
            JsonNode node = mapper.readTree(resp.body().string());
            StringBuilder sb = new StringBuilder();
            node.fields().forEachRemaining(e -> {
                if (sb.length() > 0) sb.append("  |  ");
                sb.append(e.getKey()).append(": ").append(e.getValue().asText());
            });
            return sb.length() > 0 ? sb.toString() : "no providers configured";
        }
    }

    // ── FORENSIC CASES ────────────────────────────────────────────────────

    public List<CaseItem> fetchCases() throws IOException {
        return fetchCases("/api/forensics/cases");
    }
    public List<CaseItem> fetchCasesByStatus(String status) throws IOException {
        return fetchCases("/api/forensics/cases?status=" + status);
    }
    public List<CaseItem> fetchCasesBySuspectIp(String ip) throws IOException {
        return fetchCases("/api/forensics/cases?suspectIp=" + ip);
    }

    private List<CaseItem> fetchCases(String path) throws IOException {
        List<CaseItem> list = new ArrayList<>();

        for (JsonNode n : mapper.readTree(get(path))) {

            CaseItem item = new CaseItem(
                longOf(n, "id", 0L),
                textOf(n, "caseNumber", ""),
                textOf(n, "title", ""),
                textOf(n, "status", ""),
                textOf(n, "severity", ""),
                textOf(n, "suspectIp", ""),
                textOf(n, "suspectMac", ""),
                textOf(n, "threatType", ""),
                textOf(n, "assignedTo", ""),
                formatTs(textOf(n, "openedAt", "")),
                textOf(n, "findings", "")
            );

            item.setAlertCount(longOf(n, "alertCount", 0));

            list.add(item);
        }

        return list;
    }

    public void createCase(String title, String description, String suspectIp,
                            String suspectMac, String severity, String threatType)
            throws IOException {
        String body = mapper.writeValueAsString(Map.of(
            "title", title,
            "description", description,
            "suspectIp", suspectIp,
            "suspectMac", suspectMac,
            "severity", severity,
            "threatType", threatType
        ));
        post("/api/forensics/cases", body);
    }

    public void updateCaseStatus(long id, String status, String findings)
            throws IOException {
        String body = mapper.writeValueAsString(
            Map.of("status", status, "findings", findings));
        put("/api/forensics/cases/" + id, body);
    }

    // ── FLAGGED IPs ───────────────────────────────────────────────────────

    public List<FlaggedIpItem> fetchFlaggedIps() throws IOException {
        List<FlaggedIpItem> list = new ArrayList<>();
        for (JsonNode n : mapper.readTree(get("/api/alerts/flagged-ips"))) {
            list.add(new FlaggedIpItem(
                0L,
                textOf(n, "ip", ""),
                textOf(n, "mac", ""),
                textOf(n, "organization", "Unknown"),
                textOf(n, "asn", ""),
                textOf(n, "country", ""),
                textOf(n, "threatType", ""),
                textOf(n, "protocol", ""),
                textOf(n, "severity", ""),
                intOf(n, "hits", 0),
                textOf(n, "lastSeen", "")
            ));
        }
        return list;
    }

    // ── IP PROFILE / TIMELINE ─────────────────────────────────────────────

    public JsonNode getIpProfile(String ip) throws Exception {
        return mapper.readTree(get("/api/alerts/ip-profile/" + ip));
    }

    public JsonNode getTimeline(String ip) throws Exception {
        return mapper.readTree(get("/api/alerts/timeline/" + ip));
    }
 // ── AUTH RETRY STATE ─────────────────────────────────────────────────
    // Set on every successful login(), cleared only by invalidateSession()
    // (an explicit logout). This lets a single rejected/expired token be
    // silently repaired without forcing the user back to the login screen —
    // see executeWithRetry() below.
    private volatile String username, password;

    // ── HTTP HELPERS ──────────────────────────────────────────────────────

    // Single-flight guard: concurrent 401s must not race into parallel /api/auth/login calls
    private final Object reLoginLock = new Object();

    private boolean silentReLogin(String tokenAtCall) {
        synchronized (reLoginLock) {
            // Another thread already logged in successfully — reuse it.
            if (!jwtToken.equals(tokenAtCall) && !jwtToken.isEmpty()) {
                return true;
            }
            if (username == null || password == null) return false;
            try {
                return login(username, password);
            } catch (IOException e) {
                return false;
            }
        }
    }

    /** Executes an HTTP call; on a single 401, silently re-authenticates with
     *  the stored credentials and retries exactly once. requestBuilder is a
     *  Supplier, not a plain Request, because OkHttp Requests are immutable —
     *  the retry must rebuild the Authorization header with the fresh token,
     *  not resend the one that just got rejected. */
    private Response executeWithRetry(java.util.function.Supplier<Request> requestBuilder) throws IOException {
        // Capture the token used for this call so silentReLogin can tell whether
        // another thread already refreshed it (avoids duplicate login storms).
        String tokenAtCall = jwtToken;
        Response resp = http.newCall(requestBuilder.get()).execute();
        if (resp.code() == 401) {
            resp.close();
            if (silentReLogin(tokenAtCall)) {
                resp = http.newCall(requestBuilder.get()).execute();
            } else {
                throw new IOException("Session expired — please log in again");
            }
        }
        return resp;
    }

    private String get(String path) throws IOException {
        try (Response resp = executeWithRetry(() -> new Request.Builder()
                .url(baseUrl + path)
                .addHeader("Authorization", "Bearer " + jwtToken)
                .get().build())) {
            if (!resp.isSuccessful()) throw new IOException("HTTP " + resp.code());
            return resp.body().string();
        }
    }

    private void post(String path, String json) throws IOException {
        try (Response resp = executeWithRetry(() -> new Request.Builder()
                .url(baseUrl + path)
                .addHeader("Authorization", "Bearer " + jwtToken)
                .post(RequestBody.create(json, MediaType.get("application/json")))
                .build())) {
            if (!resp.isSuccessful()) throw new IOException("HTTP " + resp.code());
        }
    }

    public void put(String path, String json) throws IOException {
        try (Response resp = executeWithRetry(() -> new Request.Builder()
                .url(baseUrl + path)
                .addHeader("Authorization", "Bearer " + jwtToken)
                .put(RequestBody.create(json, MediaType.get("application/json")))
                .build())) {
            if (!resp.isSuccessful()) throw new IOException("HTTP " + resp.code());
        }
    }

    /** Raw PATCH with a pre-serialized JSON body — delegates to patchJson(),
     *  which already carries the executeWithRetry 401-repair wrapper. */
    public void patch(String path, String json) throws IOException {
        patchJson(path, json);
    }

    public void delete(String path) throws IOException {
        try (Response resp = executeWithRetry(() -> new Request.Builder()
                .url(baseUrl + path)
                .addHeader("Authorization", "Bearer " + jwtToken)
                .delete().build())) {
            if (!resp.isSuccessful()) throw new IOException("HTTP " + resp.code());
        }
    }

    private void patchJson(String path, String json) throws IOException {
        try (Response resp = executeWithRetry(() -> new Request.Builder()
                .url(baseUrl + path)
                .addHeader("Authorization", "Bearer " + jwtToken)
                .patch(RequestBody.create(json, MediaType.get("application/json")))
                .build())) {
            if (!resp.isSuccessful()) throw new IOException("HTTP " + resp.code());
        }
    }
    

    // ── JSON helpers ──────────────────────────────────────────────────────

    private static String textOf(JsonNode node, String field, String defaultValue) {
        JsonNode n = node.get(field);
        return (n != null && !n.isNull() && !n.isMissingNode()) ? n.asText() : defaultValue;
    }

    private static int intOf(JsonNode node, String field, int defaultValue) {
        JsonNode n = node.get(field);
        return (n != null && !n.isNull() && !n.isMissingNode()) ? n.asInt() : defaultValue;
    }

    private static long longOf(JsonNode node, String field, long defaultValue) {
        JsonNode n = node.get(field);
        return (n != null && !n.isNull() && !n.isMissingNode()) ? n.asLong() : defaultValue;
    }

    private static boolean boolOf(JsonNode node, String field, boolean defaultValue) {
        JsonNode n = node.get(field);
        return (n != null && !n.isNull() && !n.isMissingNode()) ? n.asBoolean() : defaultValue;
    }


    private String formatTs(String iso) {
        try {
            return FMT.format(Instant.parse(iso));
        } catch (Exception e) {
            return iso;
        }
    }

    private String encode(String s) {
        try {
            return java.net.URLEncoder.encode(s, "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }
    /**
     * Fetches one row per source IP that has ever triggered an alert,
     * for the "Create Cases from Alerts" screen. Backed by a single
     * GROUP BY query server-side — see
     * ForensicCaseService.getAlertGroupsForCaseCreation().
     */
    public List<AlertGroupItem> fetchAlertGroups() throws IOException {
        List<AlertGroupItem> list = new ArrayList<>();
        for (JsonNode n : mapper.readTree(get("/api/forensics/cases/alert-groups"))) {
            list.add(new AlertGroupItem(
                textOf(n, "sourceIp", ""),
                textOf(n, "sourceMac", ""),
                longOf(n, "alertCount", 0L),
                formatTs(textOf(n, "firstSeen", "")),
                formatTs(textOf(n, "lastSeen", "")),
                textOf(n, "threatTypes", ""),
                textOf(n, "severity", ""),
                boolOf(n, "hasExistingCase", false),
                longOf(n, "existingCaseId", 0L),
                textOf(n, "existingCaseNumber", "")
            ));
        }
        return list;
    }

    /**
     * Creates a case from all alerts belonging to one source IP, or
     * returns the existing case if one is already open for that IP —
     * see the idempotency note on ForensicCaseService.createFromIpGroup().
     * We re-fetch by suspectIp afterward rather than trying to parse the
     * POST response body, so this works identically whether the backend
     * just created a case or handed back a pre-existing one.
     */
    public JsonNode createCaseFromIp(String ip) throws IOException {
        post("/api/forensics/cases/from-ip/" + encode(ip), "{}");
        JsonNode matches = mapper.readTree(get("/api/forensics/cases?suspectIp=" + ip));
        return matches.isArray() && matches.size() > 0 ? matches.get(0) : matches;
    }

    /**
     * Fetches every alert exchanged between two IPs, in either direction,
     * for the "View Conversation" window in IpInvestigationPanel.
     *
     * FIX: this used to be an unimplemented stub returning null, which caused
     * a NullPointerException in populateConversationWindow() the moment
     * anyone clicked "View Conversation" (the Task reported success since
     * no exception was thrown, so the failure handler never caught it).
     *
     * There's no dedicated /api/alerts?destIp= filter on the backend, so
     * rather than add a new endpoint we reuse the existing sourceIp filter
     * twice (A as source / B as dest, then B as source / A as dest) and
     * merge client-side. This keeps the fix contained to the desktop client
     * and doesn't require touching the Spring controller.
     */
    public List<AlertItem> fetchConversation(String srcIp, String destIp) throws IOException {
        List<AlertItem> result = new ArrayList<>();

        for (AlertItem item : fetchBySourceIp(srcIp)) {
            if (destIp.equals(item.getDestIp())) result.add(item);
        }
        for (AlertItem item : fetchBySourceIp(destIp)) {
            if (srcIp.equals(item.getDestIp())) result.add(item);
        }

        // Timestamps are already formatted "yyyy-MM-dd HH:mm:ss", so a plain
        // string comparison sorts them chronologically without re-parsing.
        result.sort(Comparator.comparing(AlertItem::getTimestamp));
        return result;
    }
}