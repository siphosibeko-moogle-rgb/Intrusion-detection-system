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

    // FIX: no hardcoded fallback. A hardcoded subnet/gateway baked into
    // source is fine on your own dev box, but it's a silent-wrong-answer
    // trap the moment this runs anywhere else (a customer deployment, a
    // second engine instance, CI). If ids-whitelist.properties is missing
    // or fails to load, these stay null and isInternal() is null-guarded
    // below to fail SAFE (treat nothing as internal, log loudly) rather
    // than fail QUIET (silently match your home subnet's string prefix
    // against a network it was never configured for).
    private String       subnet         = null;
    private String       gateway        = null;
    private List<String> dockerSubnets  = new ArrayList<>();

    // trustedScanners is reused by NmapScanDetector, HttpAnomalyDetector,
    // LateralMovementDetector, LowAndSlowScanDetector, and SqlInjectionDetector —
    // the underlying concept is the same in all five: "this host is authorized
    // to do things that structurally look like an attack." One list, one
    // concept, rather than five near-duplicate allowlists that drift apart.
    private final Set<String> internalServers            = new HashSet<>();
    private final Set<String> trustedScanners             = new HashSet<>();
    private final Set<String> beaconTrustedDestinations   = new HashSet<>();

    // FIX: replaces RogueDHCPDetector's auto-learn mode, which trusted
    // whichever DHCP server answered FIRST after startup — a real security
    // bypass, since DHCP-spoofing attacks work by racing the legitimate
    // server to answer first. Trusted DHCP server MACs must now be
    // configured explicitly; there is no automatic/implicit trust path.
    private final Set<String> trustedDhcpServerMacs = new HashSet<>();

    // Loose but effective: 6 groups of 2 hex chars, separated by ':' or '-'.
    // Not RFC-perfect (doesn't reject e.g. locally-administered bit nuances),
    // but it's exactly enough to reject "this is obviously not a MAC" input
    // like an IPv4 address — which is precisely the failure mode we hit.
    private static final java.util.regex.Pattern MAC_PATTERN =
        java.util.regex.Pattern.compile(
            "^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$");

    private final HttpClient httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .build();

    private final Set<String> trustedIps =
        Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final Set<String> trustedMacs =
        Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final Set<String> approvedOrgIps =
        Collections.newSetFromMap(new ConcurrentHashMap<>());

    // CIDR-shaped org-whitelist entries ("104.16.0.0/13" for Cloudflare,
    // "8.8.8.0/24", AWS ranges, …). Populated from the SAME backend
    // org-whitelist as approvedOrgIps — an admin adds a row whose "ip" field
    // is a CIDR block and the engine picks it up on the next refresh. This
    // is what makes trusted infrastructure (CDN/cloud provider ranges)
    // manageable through the application instead of per-IP or in code.
    private final java.util.concurrent.CopyOnWriteArrayList<CidrMatcher> approvedOrgCidrs =
        new java.util.concurrent.CopyOnWriteArrayList<>();

    /**
     * One row of the trusted_networks table: a curated provider range
     * (Cloudflare/AWS/Google/Azure/…) loaded from GET /api/trusted-networks.
     * suppressBeaconing is per-range and defaults to false backend-side:
     * a provider match quiets unknown-IP/rogue-IP noise only — it must NOT
     * silence BeaconingDetector unless an admin explicitly opted that range in.
     */
    public record TrustedNetworkRange(CidrMatcher cidr, String provider,
                                      boolean suppressBeaconing) {}

    // Replaced wholesale on each successful refresh; kept as-is (last known
    // good) when the backend is unreachable. volatile so packet threads see
    // a consistent, fully-built list — never a half-loaded one.
    private volatile List<TrustedNetworkRange> trustedNetworkRanges = List.of();

    public NetworkWhitelist() {
        loadProperties();
    }

    public NetworkWhitelist(String backendUrl, String backendToken) {
        this.backendUrl   = backendUrl;
        this.backendToken = backendToken != null ? backendToken : "";
        loadProperties();
        loadTrustedDevicesFromBackend();
        loadApprovedOrgsFromBackend();
        loadTrustedNetworksFromBackend();
    }

    public void refresh() {
        trustedIps.clear();
        trustedMacs.clear();
        approvedOrgIps.clear();
        approvedOrgCidrs.clear();
        loadTrustedDevicesFromBackend();
        loadApprovedOrgsFromBackend();
        loadTrustedNetworksFromBackend();
    }

    private void loadProperties() {
        try (java.io.InputStream in = getClass().getClassLoader()
                .getResourceAsStream("ids-whitelist.properties")) {
            if (in == null) {
                System.err.println("[Whitelist] ids-whitelist.properties not found — "
                    + "network.subnet/network.gateway are UNSET. isInternal() will "
                    + "treat ALL traffic as external until this file is present.");
                return;
            }
            java.util.Properties p = new java.util.Properties();
            p.load(in);
            workStart    = Integer.parseInt(p.getProperty("work.hours.start", "8"));
            workEnd      = Integer.parseInt(p.getProperty("work.hours.end",   "18"));
            timezone     = p.getProperty("work.timezone", "Africa/Johannesburg");
            weekendAlert = Boolean.parseBoolean(p.getProperty("work.weekend.alert", "true"));

            // FIX: no fallback default — see field comment above. getProperty()
            // with no default returns null on a missing key, which is exactly
            // what we want here: an explicit, checkable "not configured" state.
            subnet  = p.getProperty("network.subnet");
            gateway = p.getProperty("network.gateway");

            if (subnet == null || subnet.isBlank()) {
                System.err.println("[Whitelist] WARNING: network.subnet not set in "
                    + "ids-whitelist.properties — isInternal() will treat ALL "
                    + "traffic as external until this is configured.");
                subnet = null;
            }
            if (gateway == null || gateway.isBlank()) {
                System.err.println("[Whitelist] WARNING: network.gateway not set in "
                    + "ids-whitelist.properties.");
                gateway = null;
            }

            String dockerSubnetsProp = p.getProperty("network.docker.subnets", "");
            if (!dockerSubnetsProp.isBlank()) {
                for (String s : dockerSubnetsProp.split(",")) {
                    String trimmed = s.trim();
                    if (!trimmed.isEmpty()) dockerSubnets.add(trimmed);
                }
            }

            // server.1=10.0.0.10  server.2=10.0.0.11 ...
            for (String name : p.stringPropertyNames()) {
                if (name.matches("server\\.\\d+")) {
                    String ip = p.getProperty(name, "").trim();
                    if (!ip.isEmpty()) internalServers.add(ip);
                }
            }

            // network.trusted.scanners=10.0.0.50,10.0.0.51
            String trustedScannersProp = p.getProperty("network.trusted.scanners", "");
            if (!trustedScannersProp.isBlank()) {
                for (String s : trustedScannersProp.split(",")) {
                    String trimmed = s.trim();
                    if (!trimmed.isEmpty()) trustedScanners.add(trimmed);
                }
            }

            // network.beacon.trusted.destinations=10.0.0.5,203.0.113.9
            String beaconProp = p.getProperty("network.beacon.trusted.destinations", "");
            if (!beaconProp.isBlank()) {
                for (String s : beaconProp.split(",")) {
                    String trimmed = s.trim();
                    if (!trimmed.isEmpty()) beaconTrustedDestinations.add(trimmed);
                }
            }

            // FIX: replaces RogueDHCPDetector's auto-learn mode entirely.
            // MACs of legitimate DHCP servers (including any redundant/HA
            // pair) must be listed explicitly.
            //   network.dhcp.trusted.servers=aa:bb:cc:dd:ee:ff,11:22:33:44:55:66
            String dhcpProp = p.getProperty("network.dhcp.trusted.servers", "");
            if (!dhcpProp.isBlank()) {
                for (String s : dhcpProp.split(",")) {
                    String trimmed = s.trim().toLowerCase();
                    if (trimmed.isEmpty()) continue;
                    if (!MAC_PATTERN.matcher(trimmed).matches()) {
                        // FAIL LOUD: an entry that isn't MAC-shaped (e.g. an IP
                        // address pasted in by mistake) would otherwise sit in the
                        // set silently and never match anything, leaving
                        // RogueDHCPDetector effectively unconfigured with no signal
                        // that anything is wrong. This is exactly the bug class that
                        // caused the original getGateway()-into-MAC-constructor
                        // failure — refuse to repeat it here.
                        System.err.println("[Whitelist] IGNORING invalid entry in "
                            + "network.dhcp.trusted.servers: '" + trimmed + "' does "
                            + "not look like a MAC address (expected format "
                            + "aa:bb:cc:dd:ee:ff). Fix ids-whitelist.properties.");
                        continue;
                    }
                    trustedDhcpServerMacs.add(trimmed);
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
                System.out.println("[Whitelist] Trusted scanners/automation hosts: " + trustedScanners);
            if (!beaconTrustedDestinations.isEmpty())
                System.out.println("[Whitelist] Trusted beacon destinations: " + beaconTrustedDestinations);
            if (trustedDhcpServerMacs.isEmpty()) {
                System.err.println("[Whitelist] WARNING: no network.dhcp.trusted.servers configured — "
                    + "RogueDHCPDetector will alert on EVERY DHCP server response, including your "
                    + "legitimate one, until this is set. A noisy default is safer than silently "
                    + "trusting whichever DHCP server answers first.");
            } else {
                System.out.println("[Whitelist] Trusted DHCP servers: " + trustedDhcpServerMacs);
            }

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
                        String n = normalize(ip);
                        // An entry containing "/" is a CIDR block (e.g. a
                        // Cloudflare/AWS range added by an admin); anything
                        // else stays an exact-IP match as before.
                        if (n.contains("/")) {
                            CidrMatcher cidr = CidrMatcher.parse(n);
                            if (cidr != null) {
                                approvedOrgCidrs.add(cidr);
                                count++;
                            } else {
                                System.err.println("[Whitelist] IGNORING invalid "
                                    + "CIDR in org whitelist: '" + n + "'");
                            }
                        } else {
                            approvedOrgIps.add(n);
                            count++;
                        }
                    }
                }
                System.out.printf("[Whitelist] Loaded %d approved org IPs/ranges "
                    + "(%d CIDR blocks)%n", count, approvedOrgCidrs.size());
            }
        } catch (Exception e) {
            System.err.println("[Whitelist] Could not load org whitelist: " + e.getMessage());
        }
    }

    private void loadTrustedNetworksFromBackend() {
        if (backendToken.isBlank()) return;
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(backendUrl + "/api/trusted-networks"))
                .header("Authorization", backendToken)
                .timeout(Duration.ofSeconds(5))
                .GET()
                .build();

            HttpResponse<String> response = httpClient.send(request,
                HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                System.err.println("[Whitelist] Could not load trusted networks: "
                    + "backend returned HTTP " + response.statusCode()
                    + " — keeping previous " + trustedNetworkRanges.size() + " range(s)");
                return;
            }

            com.fasterxml.jackson.databind.ObjectMapper mapper =
                new com.fasterxml.jackson.databind.ObjectMapper();
            com.fasterxml.jackson.databind.JsonNode arr =
                mapper.readTree(response.body());

            // Build the full list first, then swap — a parse failure or a
            // transient backend hiccup must never wipe the trust the packet
            // path is currently using (same keep-last-known-good behavior
            // as the other backend loads in this class).
            List<TrustedNetworkRange> loaded = new ArrayList<>();
            for (com.fasterxml.jackson.databind.JsonNode node : arr) {
                if (!node.path("enabled").asBoolean(false)) continue;
                String cidrText = node.path("cidr").asText(null);
                if (cidrText == null || cidrText.isBlank()) continue;
                CidrMatcher cidr = CidrMatcher.parse(cidrText);
                if (cidr == null) {
                    System.err.println("[Whitelist] IGNORING invalid CIDR in "
                        + "trusted_networks: '" + cidrText + "'");
                    continue;
                }
                loaded.add(new TrustedNetworkRange(cidr,
                    node.path("provider").asText("?"),
                    node.path("suppressBeaconing").asBoolean(false)));
            }
            trustedNetworkRanges = List.copyOf(loaded);
            System.out.printf("[Whitelist] Loaded %d trusted network range(s)%n",
                loaded.size());

        } catch (Exception e) {
            System.err.println("[Whitelist] Could not load trusted networks: "
                + e.getMessage() + " — keeping previous "
                + trustedNetworkRanges.size() + " range(s)");
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
        String n = normalize(ip);
        if (approvedOrgIps.contains(n)) return true;
        if (approvedOrgCidrs.isEmpty()) return false;
        long v = CidrMatcher.ipv4ToLong(n);
        for (CidrMatcher cidr : approvedOrgCidrs) {
            if (cidr.matches(v)) return true;
        }
        return false;
    }

    /**
     * True if this IP falls inside any ENABLED trusted_networks range
     * (Cloudflare/AWS/Google/Azure/… CIDRs curated by an admin).
     *
     * SCOPE — deliberately narrow: this only quiets unknown-IP / rogue-IP
     * noise in WhitelistViolationDetector. Do NOT use it as a bypass in any
     * other detector (scan detection, SQLi, brute force, DNS, HTTP payload
     * analysis) — C2 infrastructure hides on big-provider ranges precisely
     * because defenders whitelist them. Beaconing has its own per-range
     * opt-in via isBeaconingSuppressed().
     *
     * Plain O(n) scan: the range count is dozens, not millions, and the
     * per-range check is a masked compare on a pre-parsed long.
     */
    public boolean isTrustedNetwork(String ip) {
        if (ip == null) return false;
        List<TrustedNetworkRange> ranges = trustedNetworkRanges;
        if (ranges.isEmpty()) return false;
        long v = CidrMatcher.ipv4ToLong(normalize(ip));
        if (v < 0) return false;
        for (TrustedNetworkRange range : ranges) {
            if (range.cidr().matches(v)) return true;
        }
        return false;
    }

    /**
     * True only if a matching trusted_networks range has
     * suppress_beaconing explicitly set. A provider match alone returns
     * false — BeaconingDetector keeps watching those destinations.
     */
    public boolean isBeaconingSuppressed(String ip) {
        if (ip == null) return false;
        List<TrustedNetworkRange> ranges = trustedNetworkRanges;
        if (ranges.isEmpty()) return false;
        long v = CidrMatcher.ipv4ToLong(normalize(ip));
        if (v < 0) return false;
        for (TrustedNetworkRange range : ranges) {
            if (range.suppressBeaconing() && range.cidr().matches(v)) return true;
        }
        return false;
    }

    public boolean isInternal(String ip) {
        if (ip == null) return false;
        String n = normalize(ip);
        // FIX: null-guarded. subnet is null whenever network.subnet wasn't
        // configured (see loadProperties). Without this guard, the first
        // packet processed after a missing/failed config load throws an
        // NPE inside every detector that calls isInternal() — a startup
        // config problem should degrade to "nothing is internal" (safe,
        // loud in the logs already) rather than crash the detection path.
        if (subnet != null && matchesSubnetEntry(subnet, n)) return true;
        for (String dockerSubnet : dockerSubnets) {
            if (matchesSubnetEntry(dockerSubnet, n)) return true;
        }
        return false;
    }

    // Subnet config entries accept two forms:
    //  - CIDR ("192.168.8.0/24") — exact-boundary matching, preferred.
    //  - Legacy dotted prefix ("192.168.8.") — kept for existing configs.
    //    CAUTION with the legacy form: a prefix without a trailing dot
    //    ("10.0.1") string-matches 10.0.10.x and 10.0.100.x too. Prefer
    //    CIDR, or at least end the prefix with a dot.
    private static boolean matchesSubnetEntry(String entry, String normalizedIp) {
        if (entry.contains("/")) {
            CidrMatcher cidr = CidrMatcher.parse(entry);
            return cidr != null && cidr.matches(normalizedIp);
        }
        return normalizedIp.startsWith(entry);
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

    public String  getGateway()        {
    	return gateway; }
    public String  getSubnet()         { 
    	return subnet; }
    public List<String> getInternalServers() { 
    	return new ArrayList<>(internalServers); }
    public int     getWorkStartHour()  { return workStart; }
    public int     getWorkEndHour()    { return workEnd; }
    public String  getWorkTimezone()   { return timezone; }
    public boolean isWeekendAlert()    { return weekendAlert; }
    public int     getWorkStart()      { return workStart; }
    public int     getWorkEnd()        { return workEnd; }
    public void    addTrusted(String ip, Object ignored) { addTrustedIp(ip); }

    public boolean isTrustedBeaconDestination(String dstIP) {
        return dstIP != null && beaconTrustedDestinations.contains(normalize(dstIP));
    }

    public boolean isKnownServer(String srcIP) {
        return srcIP != null && internalServers.contains(normalize(srcIP));
    }

    /**
     * True if this IP is authorized to do things that structurally look
     * like an attack: port sweeps, distributed slow scans, scanner
     * User-Agents, or multi-host admin-port connections. Covers both
     * vulnerability scanners AND configuration-management/automation
     * control nodes (Ansible, Chef, Puppet, SaltStack) — both are
     * legitimate, both look identical to an attacker to a behavior-based
     * detector.
     */
    public boolean isTrustedScanner(String srcIP) {
        return srcIP != null && trustedScanners.contains(normalize(srcIP));
    }

    /**
     * True if this MAC is a configured, legitimate DHCP server.
     *
     * FIX: replaces RogueDHCPDetector's old auto-learn behavior, which
     * trusted whichever DHCP server answered first after startup — a real
     * bypass, since DHCP-spoofing attacks work by racing the legitimate
     * server. There is no implicit trust path anymore: if this set is
     * empty, RogueDHCPDetector alerts on every DHCP server response,
     * including your real one, until network.dhcp.trusted.servers is set.
     */
    public boolean isTrustedDhcpServer(String mac) {
        return mac != null && trustedDhcpServerMacs.contains(mac.toLowerCase().trim());
    }

}