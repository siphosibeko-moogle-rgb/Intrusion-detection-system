package com.ids.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.alerts.AlertManager;
import com.ids.detectors.*;
import com.ids.network.NetworkWhitelist;
import com.ids.models.PacketContext;

import org.pcap4j.core.*;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.packet.Packet;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * IDS Engine — orchestrates all detectors over live Pcap4J packet capture.
 *
 * Usage: sudo java -jar ids-engine.jar [interface] [backend-url]
 * Example: sudo java -jar ids-engine.jar eth0 http://localhost:8080
 *
 * Required environment variables:
 *   IDS_ENGINE_USER  — backend login username (default: admin)
 *   IDS_ENGINE_PASS  — backend login password (REQUIRED, no default)
 */
public class IDSEngine {

    private static final String BPF_FILTER = "icmp or tcp or udp or arp";
    private static final int    SNAP_LEN   = 65536;
    private static final int    TIMEOUT_MS = 10;
    private static final String LOG_FILE   = "/app/logs/ids-alerts.log";

    // ── Detectors ────────────────────────────────────────────────────────────
    private IcmpAbuseDetector            icmpDetector;
    private NmapScanDetector             nmapDetector;
    private WhitelistViolationDetector   whitelistDetector;
    private ArpSpoofingDetector          arpDetector;
    private DnsTunnelingDetector         dnsDetector;
    private DataExfiltrationDetector     exfilDetector;
    private AfterHoursDetector           afterHoursDetector;
    private BruteForceDetector           bruteForceDetector;
    private BeaconingDetector            beaconingDetector;
    private LateralMovementDetector      lateralMovementDetector;
    private HttpAnomalyDetector          httpAnomalyDetector;
    private RogueDHCPDetector            rogueDhcpDetector;
    private FileTransferDetector         fileTransferDetector;
    private DataStagingDetector          dataStagingDetector;
    private UserBehaviorAnomalyDetector  ubaDetector;
    private LowAndSlowScanDetector       lowSlowDetector;
    private PortKnockingDetector         portKnockingDetector;
    private SqlInjectionDetector sqlInjectionDetector;
    private SynFloodDetector synFloodDetector;

    private final List<Detector> detectors = new ArrayList<>();

    private AlertManager      alertManager;
    private NetworkWhitelist  whitelist;
    private PcapHandle        pcapHandle;
    private Thread            alertThread;
    private String            backendToken;

    // FIX 1 — AtomicLong counter replaces per-drop stderr logging.
    // Reported every 5 minutes by the scheduler instead of spamming stderr
    // on every dropped packet under load.
    private final AtomicLong droppedPackets = new AtomicLong(0);

    // FIX 2 — ObjectMapper lives here so loginToBackend() can use it for
    // safe JWT extraction. Jackson is already on the classpath via AlertManager.
    private final ObjectMapper mapper = new ObjectMapper();

    // ── Packet queue ─────────────────────────────────────────────────────────
    private final BlockingQueue<Packet> packetQueue = new ArrayBlockingQueue<>(10_000);
    private final ExecutorService       workers     = Executors.newFixedThreadPool(2, r -> {
        Thread t = new Thread(r, "ids-worker");
        t.setDaemon(false);
        return t;
    });

    private final ScheduledExecutorService scheduler =
            Executors.newSingleThreadScheduledExecutor();

    // ── Entry point ──────────────────────────────────────────────────────────

    public static void main(String[] args) throws Exception {
        printBanner();
        String iface   = args.length > 0 ? args[0] : null;
        String backend = args.length > 1 ? args[1] : "http://localhost:8080";
        new IDSEngine().start(iface, backend);
    }

    public void start(String ifaceName, String backendUrl) throws Exception {

        // 1. Authenticate
        this.backendToken = loginToBackend(backendUrl);

        // 2. AlertManager
        alertManager = new AlertManager(LOG_FILE, backendUrl);
        alertThread  = new Thread(alertManager, "AlertManager");
        alertThread.setDaemon(false);
        alertThread.start();

        // 3. Whitelist — needs token from step 1
        whitelist = new NetworkWhitelist(backendUrl, backendToken);
        // NOTE: startAutoRefresh() starts its own internal timer.
        // We do NOT also schedule whitelist::refresh in the scheduler below
        // to avoid double-refresh race conditions.
        scheduler.scheduleAtFixedRate(whitelist::refresh, 30, 30, TimeUnit.SECONDS);

        // 4. All detectors
        String subnet = whitelist.getSubnet();

        icmpDetector            = new IcmpAbuseDetector(alertManager);
        nmapDetector            = new NmapScanDetector(alertManager);
        whitelistDetector       = new WhitelistViolationDetector(
                                        alertManager, whitelist, subnet);
        arpDetector             = new ArpSpoofingDetector(
                                        alertManager, whitelist.getGateway());
        dnsDetector             = new DnsTunnelingDetector(alertManager);
        exfilDetector           = new DataExfiltrationDetector(
                                        alertManager, subnet,
                                        whitelist.getInternalServers());
        afterHoursDetector      = new AfterHoursDetector(
                                        alertManager, subnet,
                                        whitelist.getWorkStartHour(),
                                        whitelist.getWorkEndHour(),
                                        whitelist.getWorkTimezone(),
                                        whitelist.isWeekendAlert());
        bruteForceDetector      = new BruteForceDetector(alertManager, subnet);
        beaconingDetector       = new BeaconingDetector(alertManager);
        lateralMovementDetector = new LateralMovementDetector(alertManager, subnet);
        httpAnomalyDetector     = new HttpAnomalyDetector(alertManager);
        rogueDhcpDetector       = new RogueDHCPDetector(
                                        alertManager, whitelist.getGateway());
        fileTransferDetector    = new FileTransferDetector(
                                        alertManager, subnet,
                                        whitelist.getInternalServers());
        dataStagingDetector     = new DataStagingDetector(alertManager, subnet);
        ubaDetector             = new UserBehaviorAnomalyDetector(alertManager, subnet);
        lowSlowDetector         = new LowAndSlowScanDetector(alertManager);
        portKnockingDetector    = new PortKnockingDetector(alertManager);
        sqlInjectionDetector = new SqlInjectionDetector(alertManager);
        synFloodDetector = new SynFloodDetector(alertManager);

        detectors.add(icmpDetector);
        detectors.add(nmapDetector);
        detectors.add(whitelistDetector);
        detectors.add(arpDetector);
        detectors.add(dnsDetector);
        detectors.add(exfilDetector);
        detectors.add(afterHoursDetector);
        detectors.add(bruteForceDetector);
        detectors.add(beaconingDetector);
        detectors.add(lateralMovementDetector);
        detectors.add(httpAnomalyDetector);
        detectors.add(rogueDhcpDetector);
        detectors.add(fileTransferDetector);
        detectors.add(dataStagingDetector);
        detectors.add(ubaDetector);
        detectors.add(lowSlowDetector);
        detectors.add(portKnockingDetector);
        detectors.add(sqlInjectionDetector);
        detectors.add(synFloodDetector);
        

        // 5. Config summary
        System.out.println("Subnet:  " + subnet);
        System.out.println("Gateway: " + whitelist.getGateway());
        System.out.println("Backend: " + backendUrl);
        System.out.println("Log:     " + LOG_FILE);

        // 6. Open pcap interface
        PcapNetworkInterface iface = resolveInterface(ifaceName);
        System.out.println("\n[IDS] Interface : " + iface.getName());
        iface.getAddresses().stream()
            .filter(a -> a.getAddress() != null)
            .forEach(a -> System.out.println("[IDS] Address   : "
                + a.getAddress().getHostAddress()));

        pcapHandle = iface.openLive(SNAP_LEN,
            PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, TIMEOUT_MS);
        pcapHandle.setFilter(BPF_FILTER, BpfCompileMode.OPTIMIZE);

        System.out.println("\n[IDS]LIVE CAPTURE STARTED\n");

        // 7. Start worker threads
        workers.submit(this::drainQueue);
        workers.submit(this::drainQueue);

        // 8. Periodic tasks.
        //    - cleanup()       : evicts stale per-IP state from all detectors
        //    - reportDrops()   : logs how many packets were dropped (not per-drop)
        //    whitelist refresh is handled by startAutoRefresh() above — NOT here.
        scheduler.scheduleAtFixedRate(this::cleanup,      5,  5, TimeUnit.MINUTES);
        scheduler.scheduleAtFixedRate(this::reportDrops,  1,  1, TimeUnit.MINUTES);

        Runtime.getRuntime().addShutdownHook(new Thread(this::shutdown, "Shutdown"));

        // 9. Capture loop
        try {
            pcapHandle.loop(-1, (PacketListener) this::enqueue);
        } catch (InterruptedException e) {
            System.out.println("\n[IDS] Capture interrupted.");
        }
    }

    // ── Credentials from environment — never hardcoded ───────────────────────

    private String loginToBackend(String backendUrl) {
        String username = System.getenv().getOrDefault("IDS_ENGINE_USER", "admin");
        String password = System.getenv("IDS_ENGINE_PASS");

        if (password == null || password.isBlank()) {
            throw new RuntimeException(
                "[IDS] FATAL: IDS_ENGINE_PASS environment variable is not set.\n" +
                "       Set it before starting: export IDS_ENGINE_PASS=yourpassword");
        }

        try {
            String body = "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}";
            java.net.http.HttpClient client = java.net.http.HttpClient.newHttpClient();
            java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                .uri(java.net.URI.create(backendUrl + "/api/auth/login"))
                .header("Content-Type", "application/json")
                .timeout(java.time.Duration.ofSeconds(5))
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(body))
                .build();

            java.net.http.HttpResponse<String> res = client.send(req,
                java.net.http.HttpResponse.BodyHandlers.ofString());

            if (res.statusCode() == 200) {
                // FIX 3 — Use Jackson to parse the token safely.
                // The old regex: replaceAll(".*\"token\"...", "$1") would silently
                // return the ENTIRE response body if it didn't match, causing every
                // subsequent backend call to send "Bearer {full JSON}" as the header.
                JsonNode root = mapper.readTree(res.body());
                String token = root.path("token").asText();
                if (token.isEmpty()) {
                    throw new RuntimeException(
                        "Login succeeded (HTTP 200) but response is missing 'token' field.\n" +
                        "Response was: " + res.body());
                }
                System.out.println("[IDS] Backend auth successful");
                return "Bearer " + token;
            } else {
                System.err.println("[IDS] Backend auth failed: HTTP " + res.statusCode()
                    + " — " + res.body());
            }
        } catch (RuntimeException e) {
            // Re-throw our own exceptions (token missing, bad config) as-is
            throw e;
        } catch (Exception e) {
            System.err.println("[IDS] Backend auth error: " + e.getMessage());
        }
        return null;
    }

    // ── Packet queue ─────────────────────────────────────────────────────────

    private void enqueue(Packet packet) {
        if (packet == null) return;
        // FIX 1b — offer() once. If full, increment counter. No stderr spam.
        // The old code called offer() twice, inserting every packet double
        // into the queue when it had space, and logging to stderr when full.
        if (!packetQueue.offer(packet)) {
            droppedPackets.incrementAndGet();
        }
    }

    private void reportDrops() {
        long dropped = droppedPackets.getAndSet(0);
        if (dropped > 0) {
            System.err.println("[ENGINE] Dropped " + dropped
                + " packets in the last minute — consider tuning queue size or worker count.");
        }
    }

    // ── Worker thread ─────────────────────────────────────────────────────────

    private void drainQueue() {
        while (!Thread.currentThread().isInterrupted()) {
            try {
                Packet packet = packetQueue.poll(100, TimeUnit.MILLISECONDS);
                if (packet != null) process(packet);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * Routes every captured packet through all detectors.
     * Runs on worker threads, not the pcap capture thread.
     */
    private void process(Packet packet) {
        if (packet == null) return;
        try {
            PacketContext ctx = PacketParser.parse(packet);
            String proto = ctx.getProtocol();

            // ARP path — runs before whitelist gate to maintain device state
            if ("ARP".equalsIgnoreCase(proto)) {
                whitelistDetector.analyzeArp(packet);
                arpDetector.analyze(packet);
                return;
            }
            byte[] udpPayload = null;
            if ("UDP".equalsIgnoreCase(proto)) {
                udpPayload = extractUdpPayload(packet);
            }

            // Global whitelist gate — trusted source IPs skip all behavioral detectors
            if (whitelist.isTrusted(ctx.getSrcIp())) return;

            // All behavioral detectors
            icmpDetector.analyze(ctx);
            nmapDetector.analyze(ctx);
            dnsDetector.analyze(ctx, udpPayload);
            afterHoursDetector.analyze(ctx);
            whitelistDetector.analyze(ctx);
            exfilDetector.analyze(ctx);
            bruteForceDetector.analyze(ctx);
            portKnockingDetector.analyze(ctx);
            beaconingDetector.analyze(ctx);
            lateralMovementDetector.analyze(ctx);
            dataStagingDetector.analyze(ctx);
            ubaDetector.analyze(ctx);
            lowSlowDetector.analyze(ctx);

            if ("TCP".equalsIgnoreCase(proto)) {
                String httpPayload = extractHttpPayload(packet);
                sqlInjectionDetector.analyze(ctx, httpPayload);
                httpAnomalyDetector.analyze(ctx, httpPayload);
                fileTransferDetector.analyze(ctx, httpPayload);
            }

            if ("UDP".equalsIgnoreCase(proto)) {
                rogueDhcpDetector.analyze(ctx, extractUdpPayload(packet));
                rogueDhcpDetector.analyze(ctx, udpPayload);
            }

        } catch (Exception e) {
            System.err.println("[ENGINE] process() error: "
                + e.getClass().getSimpleName() + " — " + e.getMessage());
        }
    }

    private String extractHttpPayload(Packet packet) {
        try {
            org.pcap4j.packet.TcpPacket tcp =
                    packet.get(org.pcap4j.packet.TcpPacket.class);

            if (tcp == null || tcp.getPayload() == null) return null;

            byte[] raw = tcp.getPayload().getRawData();
            if (raw == null || raw.length < 4) return null;

            String text = new String(raw, java.nio.charset.StandardCharsets.UTF_8);

            if (text.startsWith("GET ")
                    || text.startsWith("POST ")
                    || text.startsWith("PUT ")
                    || text.startsWith("DELETE ")
                    || text.startsWith("HEAD ")
                    || text.startsWith("OPTIONS ")
                    || text.startsWith("PATCH ")
                    || text.startsWith("TRACE ")
                    || text.startsWith("CONNECT ")) {
                return text;
            }

        } catch (Exception ignored) {}
        return null;
    }

    private byte[] extractUdpPayload(Packet packet) {
        try {
            org.pcap4j.packet.UdpPacket udp =
                    packet.get(org.pcap4j.packet.UdpPacket.class);

            if (udp == null || udp.getPayload() == null) return null;
            return udp.getPayload().getRawData();

        } catch (Exception ignored) {}
        return null;
    }

    // ── Cleanup ───────────────────────────────────────────────────────────────

    private void cleanup() {
        detectors.forEach(Detector::cleanup);
    }

    private void shutdown() {
        System.out.println("\n[IDS] Shutting down...");
        scheduler.shutdownNow();
        workers.shutdownNow();
        if (pcapHandle != null && pcapHandle.isOpen()) {
            try { pcapHandle.breakLoop(); } catch (NotOpenException ignored) {}
            pcapHandle.close();
        }
        alertManager.stop();
        if (alertThread != null) {
            try {
                alertThread.join(5_000);
            } catch (InterruptedException ignored) {}
        }
        System.out.println("[IDS] Total alerts: " + alertManager.getTotalAlerts());
        System.out.println("[IDS] Dropped total: " + droppedPackets.get());
        System.out.println("[IDS] Log: " + LOG_FILE);
    }

    private PcapNetworkInterface resolveInterface(String name) throws PcapNativeException {
        List<PcapNetworkInterface> ifaces = Pcaps.findAllDevs();
        if (ifaces == null || ifaces.isEmpty())
            throw new RuntimeException("No network interfaces found — run as root/sudo");
        if (name != null) {
            for (PcapNetworkInterface i : ifaces)
                if (i.getName().equalsIgnoreCase(name)) return i;
            System.out.println("[IDS] Interface '" + name + "' not found. Available:");
            ifaces.forEach(i -> System.out.println("  - " + i.getName()));
        }
        for (PcapNetworkInterface i : ifaces)
            if (!i.isLoopBack() && !i.getAddresses().isEmpty()) return i;
        return ifaces.get(0);
    }

    private static void printBanner() {
        System.out.println("\033[1;36m" + """
       IDS ENGINE — Complete Intrusion Detection System""" + "\033[0m");
    }
}