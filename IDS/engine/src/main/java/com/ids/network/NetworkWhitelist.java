package com.ids.network;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class NetworkWhitelist {

    private String  backendUrl   = "http://localhost:8080";
    private String  backendToken = "";

    private int     workStart    = 8;
    private int     workEnd      = 18;
    private String  timezone     = "Africa/Johannesburg";
    private boolean weekendAlert = true;

    // Single shared client — not recreated on every refresh
    private final HttpClient httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .build();

    private final Set<String> trustedIps =
        Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final Set<String> trustedMacs =
        Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final Set<String> approvedOrgIps =
        Collections.newSetFromMap(new ConcurrentHashMap<>());

    public NetworkWhitelist() {
        loadProperties();
    }

    public NetworkWhitelist(String backendUrl, String backendToken) {
        this.backendUrl   = backendUrl;
        this.backendToken = backendToken != null ? backendToken : "";
        loadProperties();
        loadTrustedDevicesFromBackend();
        loadApprovedOrgsFromBackend();
    }

    public void refresh() {
        trustedIps.clear();
        trustedMacs.clear();
        approvedOrgIps.clear();
        loadTrustedDevicesFromBackend();
        loadApprovedOrgsFromBackend();
    }

    private void loadProperties() {
        try (java.io.InputStream in = getClass().getClassLoader()
                .getResourceAsStream("ids-whitelist.properties")) {
            if (in == null) {
                System.err.println("[Whitelist] ids-whitelist.properties not found — using defaults");
                return;
            }
            java.util.Properties p = new java.util.Properties();
            p.load(in);
            workStart    = Integer.parseInt(p.getProperty("work.hours.start", "8"));
            workEnd      = Integer.parseInt(p.getProperty("work.hours.end",   "18"));
            timezone     = p.getProperty("work.timezone", "Africa/Johannesburg");
            weekendAlert = Boolean.parseBoolean(p.getProperty("work.weekend.alert", "true"));
            System.out.println("[Whitelist] Properties loaded — work hours: "
                + workStart + ":00–" + workEnd + ":00 (" + timezone + ")");
        } catch (Exception e) {
            System.err.println("[Whitelist] Could not load properties: " + e.getMessage());
        }
    }

    private void loadTrustedDevicesFromBackend() {
        if (backendToken.isBlank()) {
            System.err.println("[Whitelist] No auth token — skipping trusted device load");
            return;
        }
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(backendUrl + "/api/my-whitelist"))
                .header("Authorization", backendToken)
                .timeout(Duration.ofSeconds(5))
                .GET()
                .build();

            HttpResponse<String> response = httpClient.send(request,
                HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                com.fasterxml.jackson.databind.ObjectMapper mapper =
                    new com.fasterxml.jackson.databind.ObjectMapper();
                com.fasterxml.jackson.databind.JsonNode arr =
                    mapper.readTree(response.body());
                for (com.fasterxml.jackson.databind.JsonNode node : arr) {
                    String ip  = node.path("ip").asText(null);
                    String mac = node.path("mac").asText(null);
                    if (ip  != null && !ip.isBlank())  addTrustedIp(ip);
                    if (mac != null && !mac.isBlank()) addTrustedMac(mac);
                }
                System.out.printf("[Whitelist] Loaded %d trusted devices%n", arr.size());
            } else {
                System.err.println("[Whitelist] Backend returned HTTP " + response.statusCode());
            }
        } catch (Exception e) {
            System.err.println("[Whitelist] Could not load trusted devices: " + e.getMessage());
        }
    }

    private void loadApprovedOrgsFromBackend() {
        if (backendToken.isBlank()) return;
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(backendUrl + "/api/org-whitelist"))
                .header("Authorization", backendToken)
                .timeout(Duration.ofSeconds(5))
                .GET()
                .build();

            HttpResponse<String> response = httpClient.send(request,
                HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                com.fasterxml.jackson.databind.ObjectMapper mapper =
                    new com.fasterxml.jackson.databind.ObjectMapper();
                com.fasterxml.jackson.databind.JsonNode arr =
                    mapper.readTree(response.body());
                int count = 0;
                for (com.fasterxml.jackson.databind.JsonNode node : arr) {
                    boolean approved = node.path("approved").asBoolean(false);
                    String  ip       = node.path("ip").asText(null);
                    if (approved && ip != null && !ip.isBlank()) {
                        approvedOrgIps.add(normalize(ip));
                        count++;
                    }
                }
                System.out.printf("[Whitelist] Loaded %d approved org IPs%n", count);
            }
        } catch (Exception e) {
            System.err.println("[Whitelist] Could not load org whitelist: " + e.getMessage());
        }
    }

    public boolean isTrusted(String ip) {
        if (ip == null) return true;
        String n = normalize(ip);
        return isSystemAddress(n) || trustedIps.contains(n);
    }

    public boolean isTrusted(String ip, String mac) {
        if (isTrusted(ip)) return true;
        return mac != null && trustedMacs.contains(mac.toLowerCase());
    }

    public boolean isApprovedOrg(String ip) {
        if (ip == null) return false;
        return approvedOrgIps.contains(normalize(ip));
    }

    public void addTrustedIp(String ip) {
        if (ip != null && !ip.isBlank()) trustedIps.add(normalize(ip));
    }

    public void addTrustedMac(String mac) {
        if (mac != null && !mac.isBlank()) trustedMacs.add(mac.toLowerCase().trim());
    }

    private boolean isSystemAddress(String n) {
        return n.startsWith("127.") || n.equals("::1")
            || n.startsWith("224.") || n.startsWith("239.")
            || n.equals("255.255.255.255");
    }

    private String normalize(String ip) {
        return ip.trim()
            .replaceAll("^/", "")
            .replaceAll(":.*$", "");
    }
    public void startAutoRefresh(long intervalSeconds) {
        java.util.concurrent.Executors
            .newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "whitelist-refresh");
                t.setDaemon(true);
                return t;
            })
            .scheduleAtFixedRate(() -> {
                try {
                    refresh();
                } catch (Exception e) {
                    System.err.println("[Whitelist] Auto-refresh failed: " + e.getMessage());
                }
            }, intervalSeconds, intervalSeconds, java.util.concurrent.TimeUnit.SECONDS);
    }

    public String  getGateway()          { return "192.168.8.1"; }
    public String  getSubnet()           { return "192.168.8."; }
    public List<String> getInternalServers() { return new ArrayList<>(); }
    public int     getWorkStartHour()    { return workStart; }
    public int     getWorkEndHour()      { return workEnd; }
    public String  getWorkTimezone()     { return timezone; }
    public boolean isWeekendAlert()      { return weekendAlert; }
    public int     getWorkStart()        { return workStart; }
    public int     getWorkEnd()          { return workEnd; }
    public void    addTrusted(String ip, Object ignored) { addTrustedIp(ip); }
}