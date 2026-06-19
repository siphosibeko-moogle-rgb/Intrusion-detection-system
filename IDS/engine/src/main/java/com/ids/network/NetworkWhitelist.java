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

    // FIX: subnet and gateway were hardcoded to "192.168.8." and "192.168.8.1".
    //
    // Why this was a bug:
    //   Docker containers run on 172.17.x.x or 172.18.x.x by default.
    //   Detectors that check if (srcIp.startsWith(subnet)) to identify "internal"
    //   traffic would NEVER match Docker IPs, misclassifying all container traffic
    //   as external. This affected DataExfiltrationDetector, BruteForceDetector,
    //   LateralMovementDetector, AfterHoursDetector, and DataStagingDetector.
    //
    // Fix: read from ids-whitelist.properties. Defaults still work for home labs
    //      but can be overridden. For a Docker environment with multiple subnets,
    //      the subnet prefix should cover the bridge network.
    //
    // Example ids-whitelist.properties entries:
    //   network.subnet=192.168.8.
    //   network.gateway=192.168.8.1
    //   network.docker.subnets=172.17.0.,172.18.0.,172.19.0.
    private String       subnet         = "192.168.8.";
    private String       gateway        = "192.168.8.1";
    private List<String> dockerSubnets  = new ArrayList<>();

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

            // FIX: read subnet and gateway from properties instead of hardcoding
            subnet  = p.getProperty("network.subnet",  "192.168.8.");
            gateway = p.getProperty("network.gateway", "192.168.8.1");

            // FIX: support multiple subnets for Docker environments
            // Property: network.docker.subnets=172.17.0.,172.18.0.
            String dockerSubnetsProp = p.getProperty("network.docker.subnets", "");
            if (!dockerSubnetsProp.isBlank()) {
                for (String s : dockerSubnetsProp.split(",")) {
                    String trimmed = s.trim();
                    if (!trimmed.isEmpty()) dockerSubnets.add(trimmed);
                }
            }

            System.out.println("[Whitelist] Properties loaded — work hours: "
                + workStart + ":00–" + workEnd + ":00 (" + timezone + ")");
            System.out.println("[Whitelist] Subnet: " + subnet + "  Gateway: " + gateway);
            if (!dockerSubnets.isEmpty())
                System.out.println("[Whitelist] Docker subnets: " + dockerSubnets);

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

    /**
     * FIX: isInternal() now considers both the primary subnet AND Docker subnets.
     *
     * Previously there was no isInternal() method — each detector did its own
     * startsWith(subnet) check. This centralizes the logic and makes Docker
     * container IPs (172.x.x.x) correctly classified as internal when configured.
     */
    public boolean isInternal(String ip) {
        if (ip == null) return false;
        String n = normalize(ip);
        if (n.startsWith(subnet)) return true;
        for (String dockerSubnet : dockerSubnets) {
            if (n.startsWith(dockerSubnet)) return true;
        }
        return false;
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

    public String  getGateway()        { return gateway; }
    public String  getSubnet()         { return subnet; }
    public List<String> getInternalServers() { return new ArrayList<>(); }
    public int     getWorkStartHour()  { return workStart; }
    public int     getWorkEndHour()    { return workEnd; }
    public String  getWorkTimezone()   { return timezone; }
    public boolean isWeekendAlert()    { return weekendAlert; }
    public int     getWorkStart()      { return workStart; }
    public int     getWorkEnd()        { return workEnd; }
    public void    addTrusted(String ip, Object ignored) { addTrustedIp(ip); }
}