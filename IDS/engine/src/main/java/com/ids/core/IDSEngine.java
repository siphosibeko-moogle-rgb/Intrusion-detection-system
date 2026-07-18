package com.ids.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.alerts.AlertManager;
import com.ids.detectors.*;
import com.ids.network.NetworkWhitelist;
import com.ids.models.PacketContext;

import org.pcap4j.core.*;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;


public class IDSEngine {

    private static final String BPF_FILTER = "icmp or tcp or udp or arp";
    private static final int    SNAP_LEN   = 65536;
    private static final int    TIMEOUT_MS = 10;
    private static final String LOG_FILE   = "/app/logs/ids-alerts.log";

    // Detectors — process() and cleanup() iterate this list; nothing else
    // dispatches by name. Adding a detector = one add() line in start().
    private final List<Detector> detectors = new ArrayList<>();

    // ARP-path detectors are the exception: process() routes raw ARP frames
    // to their analyzeArp(Packet) before the whitelist gate, because ARP
    // analysis needs Ethernet/ARP headers PacketContext doesn't carry.
    // Both are ALSO in the detectors list (whitelistDetector for its
    // behavioral analyze(ctx), arpDetector for cleanup()).
    private WhitelistViolationDetector whitelistDetector;
    private ArpSpoofingDetector        arpDetector;

    private AlertManager     alertManager;
    private NetworkWhitelist whitelist;
    private Thread           alertThread;
    private String           backendToken;

    // Multiple capture handles, one per interface
    // Previously: single PcapHandle pcapHandle (only captured one interface).
    // Now: one handle per relevant interface, each with its own capture thread.
    private final List<PcapHandle> captureHandles = new CopyOnWriteArrayList<>();

    // Futures of the capture-loop tasks. shutdown() must wait for these to
    // exit the native pcap loop before close() — closing a handle mid-loop()
    // can segfault libpcap.
    private final List<Future<?>> captureFutures = new CopyOnWriteArrayList<>();

    //Packet queue
    // All capture threads push here; drain workers pop and process.
    private final BlockingQueue<Packet> packetQueue = new ArrayBlockingQueue<>(10_000);

    // FIX: drain worker count used to be hardcoded to 2, regardless of how
    // many CPU cores the box has or how many interfaces/detectors are in
    // play. Every packet that passes the whitelist gate runs through ~15
    // behavioral detectors synchronously inside process() — with only 2
    // consumer threads, that's the actual throughput ceiling of the whole
    // engine, not any individual detector. Sizing to the core count (minus
    // 1, to leave headroom for capture threads + GC) lets the engine use
    // the hardware it's actually running on. This is a starting point, not
    // a tuned number — if you're still seeing drops in reportDrops() after
    // this, the next lever is sharding the queue by srcIP so one hot flow
    // can't starve the others, not just adding more threads.
    private static final int DRAIN_WORKERS =
            Math.max(2, Runtime.getRuntime().availableProcessors() - 1);

    // Use CachedThreadPool to scale to N capture threads + M drain
    // threads without knowing N at startup. Threads are long-lived, not churned.
    private final ExecutorService workers = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "ids-worker");
        t.setDaemon(false);
        return t;
    });

    private final ScheduledExecutorService scheduler =
            Executors.newSingleThreadScheduledExecutor();

    private final AtomicLong droppedPackets = new AtomicLong(0);
    private final ObjectMapper mapper = new ObjectMapper();

    // ── Entry point ──────────────────────────────────────────────────────────

    public static void main(String[] args) throws Exception {
        printBanner();
        // args[0] = interface name(s) or "all" — default "all"
        // args[1] = backend URL                — default http://localhost:8080
        String iface   = args.length > 0 ? args[0] : "all";
        String backend = args.length > 1 ? args[1] : "http://localhost:8080";
        new IDSEngine().start(iface, backend);
    }

    public void start(String ifaceArg, String backendUrl) throws Exception {

        // 1. Authenticate
        this.backendToken = loginToBackend(backendUrl);

        // 2. AlertManager
        alertManager = new AlertManager(LOG_FILE, backendUrl);
        alertThread  = new Thread(alertManager, "AlertManager");
        alertThread.setDaemon(false);
        alertThread.start();

        // 3. Whitelist — needs token from step 1
        whitelist = new NetworkWhitelist(backendUrl, backendToken);
        // Re-login hook: the backend JWT expires (~24h); on HTTP 401 the
        // whitelist re-authenticates once via this supplier instead of
        // silently running on stale trust data forever.
        whitelist.setTokenSupplier(() -> loginToBackend(backendUrl));
        scheduler.scheduleAtFixedRate(whitelist::refresh, 30, 30, TimeUnit.SECONDS);

        // 4. All detectors. One add() per detector — process() and cleanup()
        //    iterate the list, so this is the only place a detector is wired.
        String subnet = whitelist.getSubnet();

        whitelistDetector = new WhitelistViolationDetector(alertManager, whitelist);
        arpDetector       = new ArpSpoofingDetector(alertManager, whitelist.getGateway());

        detectors.add(new IcmpAbuseDetector(alertManager));
        detectors.add(new NmapScanDetector(alertManager, whitelist));
        detectors.add(whitelistDetector);
        detectors.add(new DnsTunnelingDetector(alertManager, whitelist));
        detectors.add(new DataExfiltrationDetector(alertManager, whitelist));
        detectors.add(new AfterHoursDetector(alertManager, whitelist,
                whitelist.getWorkStartHour(), whitelist.getWorkEndHour(),
                whitelist.getWorkTimezone(), whitelist.isWeekendAlert()));
        detectors.add(new BruteForceDetector(alertManager, whitelist));
        detectors.add(new BeaconingDetector(alertManager, whitelist));
        // was new LateralMovementDetector(alertManager, subnet) — subnet
        // is a leftover from before this detector added whitelist.isInternal()
        // and isTrustedScanner() checks; constructor takes the whitelist now.
        detectors.add(new LateralMovementDetector(alertManager, whitelist));
        detectors.add(new PortKnockingDetector(alertManager, whitelist));
        detectors.add(new DataStagingDetector(alertManager, whitelist));
        detectors.add(new UserBehaviorAnomalyDetector(alertManager, whitelist));
        detectors.add(new LowAndSlowScanDetector(alertManager, whitelist));
        detectors.add(new SynFloodDetector(alertManager));
        detectors.add(new SqlInjectionDetector(alertManager, whitelist));
        detectors.add(new HttpAnomalyDetector(alertManager, whitelist));
        detectors.add(new FileTransferDetector(alertManager, whitelist));
        // new RogueDHCPDetector(alertManager, whitelist.getGateway()) —
        // getGateway() is leftover from the old auto-learn-first-server logic,
        // which was a real bypass (an attacker racing your real DHCP server on
        // startup could get permanently trusted). Replaced with an explicit
        // whitelist.isTrustedDhcpServer(mac) allowlist check inside the detector.
        detectors.add(new RogueDHCPDetector(alertManager, whitelist));
        // ARP-path only: analyze(ctx) is a no-op; listed for cleanup().
        detectors.add(arpDetector);

        // 5. Config summary
        System.out.println("Subnet:  " + subnet);
        System.out.println("Gateway: " + whitelist.getGateway());
        System.out.println("Backend: " + backendUrl);
        System.out.println("Log:     " + LOG_FILE);

      
        List<PcapNetworkInterface> targets = resolveInterfaces(ifaceArg);

        System.out.println("\n[IDS] Capturing on " + targets.size() + " interface(s):");
        for (PcapNetworkInterface iface : targets) {
            PcapHandle handle = iface.openLive(SNAP_LEN, PromiscuousMode.PROMISCUOUS, TIMEOUT_MS);
            handle.setFilter(BPF_FILTER, BpfCompileMode.OPTIMIZE);
            captureHandles.add(handle);

            // Log each interface and its addresses for confirmation
            System.out.printf("  [+] %-20s", iface.getName());
            String addrs = iface.getAddresses().stream()
                .filter(a -> a.getAddress() != null)
                .map(a -> a.getAddress().getHostAddress())
                .collect(Collectors.joining(", "));
            System.out.println(addrs.isEmpty() ? "(no IP)" : addrs);
        }
        System.out.println("\n[IDS] LIVE CAPTURE STARTED\n");

        System.out.println("[IDS] Starting " + DRAIN_WORKERS + " drain worker(s) ("
            + Runtime.getRuntime().availableProcessors() + " CPU cores detected)");
        for (int i = 0; i < DRAIN_WORKERS; i++) {
            workers.submit(this::drainQueue);
        }

        for (PcapHandle handle : captureHandles) {
            captureFutures.add(workers.submit(() -> runCaptureLoop(handle)));
        }

        // Periodic tasks
        scheduler.scheduleAtFixedRate(this::cleanup,      5,  5, TimeUnit.MINUTES);
        scheduler.scheduleAtFixedRate(this::reportDrops,  1,  1, TimeUnit.MINUTES);

        Runtime.getRuntime().addShutdownHook(new Thread(this::shutdown, "Shutdown"));

        //Block the main thread until interrupted.
        //     The actual capture runs on worker threads now.
        try {
            Thread.currentThread().join();
        } catch (InterruptedException e) {
            System.out.println("\n[IDS] Main thread interrupted.");
        }
    }

    //Interface resolution

    /**
     * Resolves which interfaces to capture on.
     *
     * Input forms:
     *   "all"            → all relevant non-loopback interfaces (auto-detect)
     *   "eth0"           → only eth0
     *   "wlp1s0,docker0" → exactly those two
     *   null             → same as "all"
     *
     * "Relevant" means: physical (eth*, wlp*, enp*, enx*, ens*),
     * Docker bridge (docker0, br-*), or veth pairs.
     *
     * Why not capture veth* separately?
     * Docker bridge already mirrors all veth traffic — capturing veth* would
     * double-count every packet. We skip them by default.
     *
     * Why not use the "any" pseudo-interface?
     * pcap "any" uses Linux Cooked Capture (SLL) which has no Ethernet header.
     * Our PacketParser.parse() calls packet.get(EthernetPacket.class) which would
     * return null for all packets, losing MAC addresses and breaking ARP detection.
     * Per-interface capture preserves full Ethernet frames.
     */
    private List<PcapNetworkInterface> resolveInterfaces(String arg)
            throws PcapNativeException {

        List<PcapNetworkInterface> all = Pcaps.findAllDevs();
        if (all == null || all.isEmpty())
            throw new RuntimeException("No network interfaces found — run as root/sudo");

        // Explicit list: "wlp1s0,br-64344a8a0f32"
        if (arg != null && !arg.equalsIgnoreCase("all")) {
            String[] names = arg.split(",");
            List<PcapNetworkInterface> result = new ArrayList<>();
            for (String name : names) {
                String trimmed = name.trim();
                for (PcapNetworkInterface i : all) {
                    if (i.getName().equalsIgnoreCase(trimmed)) {
                        result.add(i);
                        break;
                    }
                }
                // Warn but don't crash if a named interface is missing
                boolean found = result.stream()
                    .anyMatch(i -> i.getName().equalsIgnoreCase(trimmed));
                if (!found) {
                    System.out.println("[IDS] WARNING: Interface '" + trimmed + "' not found — skipping.");
                }
            }
            if (!result.isEmpty()) return result;
            System.out.println("[IDS] No matching interfaces found. Falling back to auto-detect.");
        }

        // Auto-detect all relevant non-loopback interfaces
        List<PcapNetworkInterface> result = new ArrayList<>();
        for (PcapNetworkInterface i : all) {
            if (i.isLoopBack()) continue;
            String name = i.getName();
            boolean isPhysical = name.startsWith("eth")  || name.startsWith("wlp")
                              || name.startsWith("enp")  || name.startsWith("enx")
                              || name.startsWith("ens")  || name.startsWith("wlan");
            boolean isDockerBridge = name.startsWith("docker") || name.startsWith("br-");
            // Note: we intentionally skip veth* — the bridge interface already
            // sees all veth traffic. Capturing veth too would double every packet.
            if (isPhysical || isDockerBridge) {
                result.add(i);
            }
        }

        if (!result.isEmpty()) return result;

        // Last resort: everything non-loopback
        System.out.println("[IDS] WARNING: No standard interfaces found — capturing all non-loopback.");
        return all.stream().filter(i -> !i.isLoopBack()).collect(Collectors.toList());
    }

    //Capture loop (one per interface)

    /**
     * Runs on a dedicated worker thread. Blocks until the handle is closed.
     *
     * This is the same logic the old single-interface loop used, extracted into
     * a method so multiple threads can each own one handle.
     */
    private void runCaptureLoop(PcapHandle handle) {
        try {
            handle.loop(-1, (PacketListener) this::enqueue);
        } catch (PcapNativeException | NotOpenException e) {
            System.err.println("[ENGINE] Capture error on " + handle + ": " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // Packet queue

    private void enqueue(Packet packet) {
        if (packet == null) return;
        if (!packetQueue.offer(packet)) {
            droppedPackets.incrementAndGet();
        }
    }

    // FIX: previously this only printed when drops had *already* happened —
    // by definition too late, since a drop means a packet a detector never
    // saw. queue.size() costs nothing to check on a 1-minute schedule and
    // shows backpressure building (queue consistently >50-70% full) before
    // it turns into drops, so you can react ahead of time instead of after.
    private void reportDrops() {
        long dropped = droppedPackets.getAndSet(0);
        int queueDepth = packetQueue.size();
        int queueCapacity = queueDepth + packetQueue.remainingCapacity();

        if (dropped > 0) {
            System.err.println("[ENGINE] Dropped " + dropped
                + " packets in the last minute — queue was full (depth "
                + queueDepth + "/" + queueCapacity + "). Consider raising "
                + "DRAIN_WORKERS or the queue capacity.");
        } else if (queueDepth > queueCapacity * 0.5) {
            System.out.println("[ENGINE] Queue depth " + queueDepth + "/" + queueCapacity
                + " (" + (queueDepth * 100 / queueCapacity) + "% full) — no drops yet, "
                + "but worth watching.");
        }
    }

    //Worker thread

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
     * Runs on drain worker threads, not the pcap capture threads.
     */
    private void process(Packet packet) {
        if (packet == null) return;
        try {
            PacketContext ctx = PacketParser.parse(packet);
            String proto = ctx.getProtocol();

            // ARP path — runs before whitelist gate to maintain device state
            if ("ARP".equalsIgnoreCase(proto)) {
                whitelistDetector.analyzeArp(packet);
                arpDetector.analyzeArp(packet);
                return;
            }

            // Global whitelist gate — trusted source IPs skip behavioral detectors.
            // A null srcIp is NOT trusted (isTrusted fails closed) — the packet
            // falls through to the detectors, which null-check internally.
            if (whitelist.isTrusted(ctx.getSrcIp())) return;

            // Payloads — extracted once here, carried on the context.
            // Detectors that need them read ctx.getUdpPayload()/getHttpPayload()
            // (null when absent or not applicable).
            if ("UDP".equalsIgnoreCase(proto)) {
                ctx.setUdpPayload(extractUdpPayload(packet));
            } else if ("TCP".equalsIgnoreCase(proto)) {
                ctx.setHttpPayload(extractHttpPayload(packet));
            }

            // Behavioral detectors — uniform dispatch. Protocol/port routing
            // lives inside each detector (they all self-gate and early-return
            // on traffic that isn't theirs), not here.
            for (Detector detector : detectors) {
                detector.analyze(ctx);
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

            if (text.startsWith("GET ")     || text.startsWith("POST ")
                    || text.startsWith("PUT ")    || text.startsWith("DELETE ")
                    || text.startsWith("HEAD ")   || text.startsWith("OPTIONS ")
                    || text.startsWith("PATCH ")  || text.startsWith("TRACE ")
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

    // Auth
    private String loginToBackend(String backendUrl) {
        String username = System.getenv().getOrDefault("IDS_ENGINE_USER", "admin");
        String password = System.getenv("IDS_ENGINE_PASS");

        if (password == null || password.isBlank()) {
            throw new RuntimeException(
                "[IDS] FATAL: IDS_ENGINE_PASS environment variable is not set.\n" +
                "       Set it before starting: export IDS_ENGINE_PASS=yourpassword");
        }

        try {
            // Serialize via Jackson — string concatenation broke the request
            // body whenever the password contained a quote or backslash.
            com.fasterxml.jackson.databind.node.ObjectNode loginNode = mapper.createObjectNode();
            loginNode.put("username", username);
            loginNode.put("password", password);
            String body = mapper.writeValueAsString(loginNode);
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
            throw e;
        } catch (Exception e) {
            System.err.println("[IDS] Backend auth error: " + e.getMessage());
        }
        return null;
    }

   
    private void cleanup() {
        detectors.forEach(Detector::cleanup);
    }

    private void shutdown() {
        System.out.println("\n[IDS] Shutting down...");
        scheduler.shutdownNow();

        // Order matters: breakLoop() → wait for capture threads to leave the
        // native pcap loop → close(). Closing while a thread is inside loop()
        // can segfault libpcap.
        for (PcapHandle handle : captureHandles) {
            if (handle != null && handle.isOpen()) {
                try { handle.breakLoop(); } catch (NotOpenException ignored) {}
            }
        }
        for (Future<?> f : captureFutures) {
            try { f.get(2, TimeUnit.SECONDS); } catch (Exception ignored) {}
        }
        for (PcapHandle handle : captureHandles) {
            if (handle != null && handle.isOpen()) {
                handle.close();
            }
        }
        workers.shutdownNow();

        alertManager.stop();
        if (alertThread != null) {
            try { alertThread.join(5_000); } catch (InterruptedException ignored) {}
        }
        System.out.println("[IDS] Total alerts:  " + alertManager.getTotalAlerts());
        System.out.println("[IDS] Dropped total: " + droppedPackets.get());
        System.out.println("[IDS] Log: " + LOG_FILE);
    }

    private static void printBanner() {
        System.out.println("\033[1;36m" + """
       IDS ENGINE — Complete Intrusion Detection System""" + "\033[0m");
    }
}