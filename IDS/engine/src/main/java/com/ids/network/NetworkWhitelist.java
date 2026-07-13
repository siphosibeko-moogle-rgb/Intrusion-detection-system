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
    // volatile: replaced by the re-login path (see getWithAuthRetry) while
    // drain workers and the refresh scheduler read it concurrently.
    private volatile String backendToken = "";

    // Re-login hook (set by the engine). Used to mint a fresh JWT when the
    // backend starts returning 401 after token expiry.
    private volatile java.util.function.Supplier<String> tokenSupplier;

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

    // Volatile refs to immutable snapshots, swapped atomically on refresh
    // (build-then-swap). Readers always see a complete old or new state —
    // never a half-cleared one while the backend HTTP calls are in flight.
    private volatile Set<String> trustedIps     = Set.of();
    private volatile Set<String> trustedMacs    = Set.of();
    private volatile Set<String> approvedOrgIps = Set.of();

    // CIDR-shaped org-whitelist entries ("104.16.0.0/13" for Cloudflare,
    // "8.8.8.0/24", AWS ranges, …). Populated from the SAME backend
    // org-whitelist as approvedOrgIps — an admin adds a row whose "ip" field
    // is a CIDR block and the engine picks it up on the next refresh. This
    // is what makes trusted infrastructure (CDN/cloud provider ranges)
    // manageable through the application instead of per-IP or in code.
    private volatile List<Cidr> approvedOrgCidrs = List.of();

    // Snapshot types returned by the backend loaders (null on any failure).
    private record TrustedDevices(Set<String> ips, Set<String> macs) {}
    private record OrgWhitelist(Set<String> ips, List<Cidr> cidrs) {}

    /** IPv4 CIDR block. parse() returns null for anything malformed. */
    private record Cidr(long network, long mask) {
        static Cidr parse(String s) {
            int slash = s.indexOf('/');
            if (slash < 0) return null;
            long base = ipv4ToLong(s.substring(0, slash));
            if (base < 0) return null;
            int prefix;
            try { prefix = Integer.parseInt(s.substring(slash + 1)); }
            catch (NumberFormatException e) { return null; }
            if (prefix < 0 || prefix > 32) return null;
            long mask = prefix == 0 ? 0 : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
            return new Cidr(base & mask, mask);
        }
        boolean contains(long ip) { return ip >= 0 && (ip & mask) == network; }
    }

    /** Dotted-quad IPv4 → unsigned 32-bit value; -1 if not IPv4. */
    private static long ipv4ToLong(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return -1;
        long v = 0;
        for (String p : parts) {
            int octet;
            try { octet = Integer.parseInt(p); }
            catch (NumberFormatException e) { return -1; }
            if (octet < 0 || octet > 255) return -1;
            v = (v << 8) | octet;
        }
        return v;
    }

    public NetworkWhitelist() {
        loadProperties();
    }

    public NetworkWhitelist(String backendUrl, String backendToken) {
        this.backendUrl   = backendUrl;
        this.backendToken = backendToken != null ? backendToken : "";
        loadProperties();
        refresh();
    }

    /** Lets the engine hand us a re-login callback for JWT expiry (401). */
    public void setTokenSupplier(java.util.function.Supplier<String> tokenSupplier) {
        this.tokenSupplier = tokenSupplier;
    }

    public void refresh() {
        // Build-then-swap: never clear the live sets before the backend
        // answers. On any load failure, keep the previous complete state
        // instead of running with an empty whitelist.
        TrustedDevices devices = loadTrustedDevicesFromBackend();
        if (devices != null) {
            trustedIps  = devices.ips();
            trustedMacs = devices.macs();
        } else {
            System.err.println("[Whitelist] Trusted device refresh failed — keeping previous state");
        }
        OrgWhitelist orgs = loadApprovedOrgsFromBackend();
        if (orgs != null) {
            approvedOrgIps   = orgs.ips();
            approvedOrgCidrs = orgs.cidrs();
        } else {
            System.err.println("[Whitelist] Org whitelist refresh failed — keeping previous state");
        }
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

    // Sends an authenticated GET. On 401 (expired JWT), re-logs-in ONCE via
    // tokenSupplier and retries ONCE with the new token — no loop.
    private HttpResponse<String> getWithAuthRetry(String path) throws Exception {
        HttpResponse<String> response = sendAuthedGet(path);
        if (response.statusCode() == 401 && tokenSupplier != null) {
            System.err.println("[Whitelist] Backend returned HTTP 401 — token likely expired, re-authenticating");
            String newToken = tokenSupplier.get();
            if (newToken == null || newToken.isBlank()) {
                System.err.println("[Whitelist] RE-LOGIN FAILED — cannot refresh whitelist, keeping previous state");
                return response;
            }
            backendToken = newToken;
            response = sendAuthedGet(path);
        }
        return response;
    }

    private HttpResponse<String> sendAuthedGet(String path) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(backendUrl + path))
            .header("Authorization", backendToken)
            .timeout(Duration.ofSeconds(5))
            .GET()
            .build();
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }

    /** Builds a fresh snapshot from the backend; null on any failure (caller keeps old state). */
    private TrustedDevices loadTrustedDevicesFromBackend() {
        if (backendToken.isBlank()) {
            System.err.println("[Whitelist] No auth token — skipping trusted device load");
            return null;
        }
        try {
            HttpResponse<String> response = getWithAuthRetry("/api/my-whitelist");

            if (response.statusCode() == 200) {
                com.fasterxml.jackson.databind.ObjectMapper mapper =
                    new com.fasterxml.jackson.databind.ObjectMapper();
                com.fasterxml.jackson.databind.JsonNode arr =
                    mapper.readTree(response.body());
                Set<String> ips  = new HashSet<>();
                Set<String> macs = new HashSet<>();
                for (com.fasterxml.jackson.databind.JsonNode node : arr) {
                    String ip  = node.path("ip").asText(null);
                    String mac = node.path("mac").asText(null);
                    if (ip  != null && !ip.isBlank())  ips.add(normalize(ip));
                    if (mac != null && !mac.isBlank()) macs.add(mac.toLowerCase().trim());
                }
                System.out.printf("[Whitelist] Loaded %d trusted devices%n", arr.size());
                return new TrustedDevices(Collections.unmodifiableSet(ips),
                                          Collections.unmodifiableSet(macs));
            } else {
                System.err.println("[Whitelist] Backend returned HTTP " + response.statusCode());
            }
        } catch (Exception e) {
            System.err.println("[Whitelist] Could not load trusted devices: " + e.getMessage());
        }
        return null;
    }

    /** Builds a fresh snapshot from the backend; null on any failure (caller keeps old state). */
    private OrgWhitelist loadApprovedOrgsFromBackend() {
        if (backendToken.isBlank()) return null;
        try {
            HttpResponse<String> response = getWithAuthRetry("/api/org-whitelist");

            if (response.statusCode() == 200) {
                com.fasterxml.jackson.databind.ObjectMapper mapper =
                    new com.fasterxml.jackson.databind.ObjectMapper();
                com.fasterxml.jackson.databind.JsonNode arr =
                    mapper.readTree(response.body());
                Set<String> ips   = new HashSet<>();
                List<Cidr>  cidrs = new ArrayList<>();
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
                            Cidr cidr = Cidr.parse(n);
                            if (cidr != null) {
                                cidrs.add(cidr);
                                count++;
                            } else {
                                System.err.println("[Whitelist] IGNORING invalid "
                                    + "CIDR in org whitelist: '" + n + "'");
                            }
                        } else {
                            ips.add(n);
                            count++;
                        }
                    }
                }
                System.out.printf("[Whitelist] Loaded %d approved org IPs/ranges "
                    + "(%d CIDR blocks)%n", count, cidrs.size());
                return new OrgWhitelist(Collections.unmodifiableSet(ips),
                                        Collections.unmodifiableList(cidrs));
            }
        } catch (Exception e) {
            System.err.println("[Whitelist] Could not load org whitelist: " + e.getMessage());
        }
        return null;
    }

    public boolean isTrusted(String ip) {
        // Fail CLOSED: a packet whose source IP couldn't be parsed must not
        // be treated as trusted — that was a bypass for malformed/crafted packets.
        if (ip == null) return false;
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
        long v = ipv4ToLong(n);
        for (Cidr cidr : approvedOrgCidrs) {
            if (cidr.contains(v)) return true;
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
            Cidr cidr = Cidr.parse(entry);
            return cidr != null && cidr.contains(ipv4ToLong(normalizedIp));
        }
        return normalizedIp.startsWith(entry);
    }

    // Copy-on-write: the live sets are immutable snapshots (see field decl),
    // so adds rebuild and swap. synchronized to avoid lost concurrent adds.
    public synchronized void addTrustedIp(String ip) {
        if (ip == null || ip.isBlank()) return;
        Set<String> next = new HashSet<>(trustedIps);
        next.add(normalize(ip));
        trustedIps = Collections.unmodifiableSet(next);
    }

    public synchronized void addTrustedMac(String mac) {
        if (mac == null || mac.isBlank()) return;
        Set<String> next = new HashSet<>(trustedMacs);
        next.add(mac.toLowerCase().trim());
        trustedMacs = Collections.unmodifiableSet(next);
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