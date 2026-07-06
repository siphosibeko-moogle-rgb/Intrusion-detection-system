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

    // FIX: these three sets used to back three methods that were left as
    // auto-generated stubs returning false unconditionally — isKnownServer(),
    // isTrustedScanner(), isTrustedBeaconDestination(). That compiled fine but
    // silently defeated every detector fix that depended on them:
    //   - NmapScanDetector / HttpAnomalyDetector kept alerting on your own
    //     vulnerability scanner (isTrustedScanner always false)
    //   - DataExfiltrationDetector's "(dynamic/DHCP device)" label was always
    //     appended, even for known static servers (isKnownServer always false)
    //   - BeaconingDetector's self-exclusion never excluded anything
    //     (isTrustedBeaconDestination always false)
    // All three are now real Sets, populated from properties below.
    private final Set<String> internalServers            = new HashSet<>();
    private final Set<String> trustedScanners             = new HashSet<>();
    private final Set<String> beaconTrustedDestinations   = new HashSet<>();

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

            // FIX: actually parse server.N properties. This class's own
            // job is to be the single source of truth for "is this a known
            // internal server" — getInternalServers()/isKnownServer() were
            // both dead until now regardless of what was configured here.
            //   server.1=10.0.0.10
            //   server.2=10.0.0.11
            for (String name : p.stringPropertyNames()) {
                if (name.matches("server\\.\\d+")) {
                    String ip = p.getProperty(name, "").trim();
                    if (!ip.isEmpty()) internalServers.add(ip);
                }
            }

            // FIX: authorized internal security tools (Nessus/OpenVAS/scheduled
            // nmap compliance scans) behave identically to the attacks
            // NmapScanDetector and HttpAnomalyDetector are built to catch —
            // port sweeps and scanner User-Agents are the SAME signal whether
            // it's an attacker or your own vulnerability-management program.
            //   network.trusted.scanners=10.0.0.50,10.0.0.51
            String trustedScannersProp = p.getProperty("network.trusted.scanners", "");
            if (!trustedScannersProp.isBlank()) {
                for (String s : trustedScannersProp.split(",")) {
                    String trimmed = s.trim();
                    if (!trimmed.isEmpty()) trustedScanners.add(trimmed);
                }
            }

            // FIX: known-legitimate periodic destinations (this engine's own
            // backend, monitoring/license servers) exempted from
            // BeaconingDetector, which otherwise can't distinguish a fixed-
            // interval malware beacon from a fixed-interval monitoring agent.
            //   network.beacon.trusted.destinations=10.0.0.5,203.0.113.9
            String beaconProp = p.getProperty("network.beacon.trusted.destinations", "");
            if (!beaconProp.isBlank()) {
                for (String s : beaconProp.split(",")) {
                    String trimmed = s.trim();
                    if (!trimmed.isEmpty()) beaconTrustedDestinations.add(trimmed);
                }
            }

            System.out.println("[Whitelist] Properties loaded — work hours: "
                + workStart + ":00–" + workEnd + ":00 (" + timezone + ")");
            System.out.println("[Whitelist] Subnet: " + subnet + "  Gateway: " + gateway);
            if (!dockerSubnets.isEmpty())
                System.out.println("[Whitelist] Docker subnets: " + dockerSubnets);
            if (!internalServers.isEmpty())
                System.out.println("[Whitelist] Known internal servers: " + internalServers);
            if (!trustedScanners.isEmpty())
                System.out.println("[Whitelist] Trusted scanners: " + trustedScanners);
            if (!beaconTrustedDestinations.isEmpty())
                System.out.println("[Whitelist] Trusted beacon destinations: " + beaconTrustedDestinations);

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
            || n.equals("255.255.255.255") || n.startsWith("169.254.");
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

    // FIX: was hardcoded `return new ArrayList<>();` — always empty regardless
    // of configuration. Now backed by the real internalServers set, populated
    // from server.N properties in loadProperties().
    public List<String> getInternalServers() { return new ArrayList<>(internalServers); }

    public int     getWorkStartHour()  { return workStart; }
    public int     getWorkEndHour()    { return workEnd; }
    public String  getWorkTimezone()   { return timezone; }
    public boolean isWeekendAlert()    { return weekendAlert; }
    public int     getWorkStart()      { return workStart; }
    public int     getWorkEnd()        { return workEnd; }
    public void    addTrusted(String ip, Object ignored) { addTrustedIp(ip); }

    /**
     * True if this destination is a known-legitimate source of regular,
     * fixed-interval traffic (this engine's own backend, a monitoring or
     * license server) and should be exempt from BeaconingDetector.
     *
     * FIX: was a stub returning false unconditionally — every destination
     * used to be a beaconing candidate, including this engine's own
     * scheduled whitelist-refresh traffic to its backend.
     */
    public boolean isTrustedBeaconDestination(String dstIP) {
        return dstIP != null && beaconTrustedDestinations.contains(normalize(dstIP));
    }

    /**
     * Backed by the same server.N properties as getInternalServers().
     *
     * FIX: was a stub returning false unconditionally — DataExfiltrationDetector
     * always labeled the destination "(dynamic/DHCP device)" even when it was
     * actually another known static server, because this always said no.
     */
    public boolean isKnownServer(String srcIP) {
        return srcIP != null && internalServers.contains(normalize(srcIP));
    }

    /**
     * True if this IP is a known, authorized internal security tool
     * (vulnerability scanner, compliance scan runner). Intentionally
     * separate from isTrusted() — a scanner should be exempt from
     * scan/sweep detection specifically, without being exempt from every
     * other detector (e.g. it should still trip AfterHoursDetector if
     * someone runs it at 3am without authorization).
     *
     * FIX: was a stub returning false unconditionally — NmapScanDetector's
     * and HttpAnomalyDetector's trusted-scanner checks always failed, so
     * your own vulnerability scanner kept firing CRITICAL port-sweep and
     * scanner-User-Agent alerts against itself.
     */
    public boolean isTrustedScanner(String srcIP) {
        return srcIP != null && trustedScanners.contains(normalize(srcIP));
    }
}