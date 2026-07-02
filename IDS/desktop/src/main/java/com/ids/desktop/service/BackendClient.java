package com.ids.desktop.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.desktop.model.AlertItem;
import com.ids.desktop.model.CaseItem;
import com.ids.desktop.model.FlaggedIpItem;
import com.ids.desktop.model.MyWhitelistItem;
import com.ids.desktop.model.OrgWhitelistItem;
import okhttp3.*;

import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class BackendClient {

    private static final DateTimeFormatter FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                         .withZone(ZoneId.systemDefault());
    

    private final String       baseUrl;
    private final OkHttpClient http;
    private final ObjectMapper mapper    = new ObjectMapper();
    private       String       jwtToken = "";

    public void invalidateSession() { jwtToken = ""; }

    public BackendClient(String baseUrl) {
        this.baseUrl = baseUrl;
        this.http    = new OkHttpClient.Builder()
            .connectTimeout(8,  TimeUnit.SECONDS)
            .readTimeout(10,    TimeUnit.SECONDS)
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
            return !jwtToken.isEmpty();
        }
    }

    public boolean isLoggedIn() { return !jwtToken.isEmpty(); }
    public String  getBaseUrl() { return baseUrl; }

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

    public List<AlertItem> fetchAlerts()                         throws IOException {
        return fetchAlerts("/api/alerts");
    }
    public List<AlertItem> fetchBySeverity(String sev)           throws IOException {
        return fetchAlerts("/api/alerts?severity=" + sev);
    }
    public List<AlertItem> fetchByType(String type)              throws IOException {
        return fetchAlerts("/api/alerts?type=" + encode(type));
    }
    public List<AlertItem> fetchBySourceIp(String ip)            throws IOException {
        return fetchAlerts("/api/alerts?sourceIp=" + ip);
    }
    public List<AlertItem> fetchBySourceMac(String mac)          throws IOException {
        return fetchAlerts("/api/alerts?sourceMac=" + encode(mac));
    }
    public List<AlertItem> fetchSince(long epochMs)              throws IOException {
        return fetchAlerts("/api/alerts?sinceMs=" + epochMs);
    }

    private List<AlertItem> fetchAlerts(String path) throws IOException {
        List<AlertItem> list = new ArrayList<>();
        for (JsonNode n : mapper.readTree(get(path))) {
            list.add(new AlertItem(
                formatTs(textOf(n, "timestamp",   "")),
                textOf(n, "severity",             ""),
                textOf(n, "threatType",           ""),
                textOf(n, "sourceIp",             ""),
                textOf(n, "sourceMac",            ""),
                textOf(n, "destIp",               ""),
                textOf(n, "protocol",             ""),
                textOf(n, "requestType",          ""),
                intOf(n,  "packetCount",           0),
                textOf(n, "details",              "")
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
                formatTs(textOf(n, "lastSeen",    "")),
                textOf(n, "severity",             ""),
                textOf(n, "threatType",           ""),
                textOf(n, "sourceIp",             ""),
                textOf(n, "sourceMac",            ""),
                textOf(n, "destIp",               ""),
                textOf(n, "protocol",             ""),
                textOf(n, "requestType",          ""),
                intOf(n,  "packetCount",           0),
                textOf(n, "details",              "")
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
                longOf(n,  "id",      0L),
                textOf(n,  "ip",      ""),
                textOf(n,  "mac",     ""),
                textOf(n,  "label",   ""),
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

    // ── ORG WHITELIST ─────────────────────────────────────────────────────

    public List<OrgWhitelistItem> fetchOrgWhitelist() throws IOException {
        List<OrgWhitelistItem> list = new ArrayList<>();
        for (JsonNode n : mapper.readTree(get("/api/org-whitelist"))) {
            list.add(new OrgWhitelistItem(
                longOf(n,    "id",       0L),
                textOf(n,    "ip",       ""),
                textOf(n,    "orgName",  ""),
                textOf(n,    "asn",      ""),
                textOf(n,    "country",  ""),
                intOf(n,     "hits",      0),
                boolOf(n,    "approved", false),
                formatTs(textOf(n, "lastSeen", ""))
            ));
        }
        return list;
    }

    public void approveOrg(long id)     throws IOException { patch("/api/org-whitelist/" + id + "/approve"); }
    public void approveAllOrgs()        throws IOException { patch("/api/org-whitelist/approve-all"); }
    public void deleteOrgEntry(long id) throws IOException { delete("/api/org-whitelist/" + id); }

    // ── FORENSIC CASES ────────────────────────────────────────────────────

    public List<CaseItem> fetchCases() throws IOException {
        return fetchCases("/api/forensics/cases");
    }
    public List<CaseItem> fetchCasesByStatus(String status)    throws IOException {
        return fetchCases("/api/forensics/cases?status=" + status);
    }
    public List<CaseItem> fetchCasesBySuspectIp(String ip)     throws IOException {
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
            "title",       title,
            "description", description,
            "suspectIp",   suspectIp,
            "suspectMac",  suspectMac,
            "severity",    severity,
            "threatType",  threatType
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
                textOf(n, "ip",         ""),
                textOf(n, "mac",        ""),
                textOf(n, "threatType", ""),
                textOf(n, "protocol",   ""),
                intOf(n,  "hits",        0),
                textOf(n, "lastSeen",   "")
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

    // ── HTTP HELPERS ──────────────────────────────────────────────────────

    private String get(String path) throws IOException {
        Request req = new Request.Builder()
            .url(baseUrl + path)
            .addHeader("Authorization", "Bearer " + jwtToken)
            .get().build();
        try (Response resp = http.newCall(req).execute()) {
            if (resp.code() == 401) throw new IOException("Session expired — please log in again");
            if (!resp.isSuccessful()) throw new IOException("HTTP " + resp.code());
            return resp.body().string();
        }
    }

    private void post(String path, String json) throws IOException {
        Request req = new Request.Builder()
            .url(baseUrl + path)
            .addHeader("Authorization", "Bearer " + jwtToken)
            .post(RequestBody.create(json, MediaType.get("application/json")))
            .build();
        try (Response resp = http.newCall(req).execute()) {
            if (!resp.isSuccessful()) throw new IOException("HTTP " + resp.code());
        }
    }

    public void put(String path, String json) throws IOException {
        Request req = new Request.Builder()
            .url(baseUrl + path)
            .addHeader("Authorization", "Bearer " + jwtToken)
            .put(RequestBody.create(json, MediaType.get("application/json")))
            .build();
        try (Response resp = http.newCall(req).execute()) {
            if (!resp.isSuccessful()) throw new IOException("HTTP " + resp.code());
        }
    }

    private void patch(String path) throws IOException {
        Request req = new Request.Builder()
            .url(baseUrl + path)
            .addHeader("Authorization", "Bearer " + jwtToken)
            .patch(RequestBody.create("{}", MediaType.get("application/json")))
            .build();
        try (Response resp = http.newCall(req).execute()) {
            if (!resp.isSuccessful()) throw new IOException("HTTP " + resp.code());
        }
    }

    public void delete(String path) throws IOException {
        Request req = new Request.Builder()
            .url(baseUrl + path)
            .addHeader("Authorization", "Bearer " + jwtToken)
            .delete().build();
        try (Response resp = http.newCall(req).execute()) {
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
}