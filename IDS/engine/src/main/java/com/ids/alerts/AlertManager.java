package com.ids.alerts;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.models.ThreatEvent;
import okhttp3.*;

import java.io.*;
import java.time.LocalDateTime;
import java.util.concurrent.*;

public class AlertManager implements Runnable {

    private static final String RESET  = "\033[0m";
    private static final String RED    = "\033[0;31m";
    private static final String ORANGE = "\033[0;33m";
    private static final String YELLOW = "\033[1;33m";
    private static final String CYAN   = "\033[0;36m";
    private static final String BOLD   = "\033[1m";

    private final BlockingQueue<ThreatEvent> queue = new LinkedBlockingQueue<>();
    private volatile boolean running = true;
    private int totalAlerts = 0;

    private final String logFile;
    private final String backendUrl;
    private final OkHttpClient http;
    private final ObjectMapper mapper = new ObjectMapper();

    // FIX — BufferedWriter held open for the lifetime of AlertManager.
    // The old writeLog() opened → appended → closed the file on EVERY alert.
    // At high alert rates that creates constant file descriptor churn.
    // One open writer, flushed per alert, closed only on stop().
    private BufferedWriter logWriter;

    // FIX — Engine API key read from environment, not hardcoded in source.
    // The old value "ids-engine-secret-key-2024" was extractable from the JAR
    // with: strings engine-1.0.0.jar | grep ids-engine
    private final String engineApiKey = System.getenv()
            .getOrDefault("IDS_ENGINE_APIKEY", "ids-engine-dev-key-replace-in-prod");

    private final ConcurrentHashMap<String, Long> cooldowns = new ConcurrentHashMap<>();
    private static final long COOLDOWN_MS = 3_000L;

    public AlertManager(String logFile, String backendUrl) {
        this.logFile     = logFile;
        this.backendUrl  = backendUrl;

        this.http = new OkHttpClient.Builder()
            .connectTimeout(3, TimeUnit.SECONDS)
            .callTimeout(5, TimeUnit.SECONDS)
            .build();

        initLog();
    }

    private void initLog() {
        try {
            File f = new File(logFile).getAbsoluteFile();
            File parent = f.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }

            // Write the session header (overwrite on startup, append=false)
            try (PrintWriter pw = new PrintWriter(new FileWriter(f, false))) {
                pw.println("=".repeat(80));
                pw.println("  IDS Alert Log — Started: " + LocalDateTime.now());
                pw.println("=".repeat(80));
                pw.flush();
                System.out.println("[AlertManager] Log file: " + f.getAbsolutePath());
            }

            // Now open the persistent writer in append mode.
            // All subsequent writeLog() calls use this — no open/close per alert.
            logWriter = new BufferedWriter(new FileWriter(f, true));

        } catch (IOException e) {
            System.err.println("[AlertManager] Log init failed: " + e.getMessage());
        }
    }

    public void raise(ThreatEvent event) {
        // FIX — cooldown key includes ThreatType AND dstPort so simultaneous
        // multi-vector attacks from the same IP (e.g. brute force + port scan)
        // each get their own cooldown bucket and are not silently merged.
        String key = event.getType().name() + ":" + event.getSourceIP() + ":" + event.getDestinationPort();
        long now = System.currentTimeMillis();
        Long last = cooldowns.get(key);
        if (last != null && (now - last) < COOLDOWN_MS) return;
        cooldowns.put(key, now);
        queue.offer(event);
    }

    @Override
    public void run() {
        System.out.println("[AlertManager] Processing thread started.");
        while (running || !queue.isEmpty()) {
            try {
                ThreatEvent e = queue.poll(100, TimeUnit.MILLISECONDS);
                if (e != null) {
                    printConsole(e);
                    writeLog(e);
                    postToBackend(e);
                    totalAlerts++;
                }
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        System.out.println("[AlertManager] Thread exited. Total alerts: " + totalAlerts);
    }

    private void printConsole(ThreatEvent e) {
        String color = switch (e.getSeverity()) {
            case CRITICAL -> RED;
            case HIGH     -> ORANGE;
            case MEDIUM   -> YELLOW;
            case LOW      -> CYAN;
        };
        String border = color + BOLD + "█".repeat(70) + RESET;
        System.out.println(border);
        System.out.printf("%s%s %-32s  [%s]%s%n", color, BOLD, e.getType().name(), e.getSeverity(), RESET);
        System.out.printf("%s  ├─ Source IP  : %s%-18s%s  MAC: %s%s%n", color, BOLD, e.getSourceIP(), RESET, e.getSourceMac(), RESET);
        System.out.printf("%s  ├─ Dest IP    : %-20s%s%n", color, e.getDestinationIP(), RESET);
        System.out.printf("%s  ├─ Protocol   : %-10s  Packets: %d%s%n", color, e.getProtocol(), e.getPacketCount(), RESET);
        System.out.printf("%s  └─ %s%s%n", color, e.getDetails(), RESET);
        System.out.println(border + "\n");
    }

    private void writeLog(ThreatEvent e) {
        // FIX — use the persistent logWriter opened in initLog().
        // No file open/close on every alert. Flush per alert for durability
        // (ensures the line is on disk even if the JVM crashes).
        if (logWriter == null) return;
        try {
            logWriter.write(e.toString());
            logWriter.newLine();
            logWriter.flush();
        } catch (IOException ex) {
            System.err.println("[AlertManager] writeLog FAILED: " + ex.getMessage());
        }
    }

    private void postToBackend(ThreatEvent e) {
        if (backendUrl == null || backendUrl.isBlank()) return;

        try {
            String json = mapper.writeValueAsString(e.toMap());
            RequestBody body = RequestBody.create(
                json,
                MediaType.parse("application/json")
            );
            Request req = new Request.Builder()
                    .url(backendUrl + "/api/alerts/ingest")
                    // FIX — key comes from env var, not hardcoded string
                    .addHeader("X-Engine-Key", engineApiKey)
                    .post(body)
                    .build();

            http.newCall(req).enqueue(new Callback() {
                @Override
                public void onFailure(Call call, IOException ex) {
                    System.err.println("[AlertManager] Failed to send alert: " + ex.getMessage());
                }

                @Override
                public void onResponse(Call call, Response res) {
                    if (!res.isSuccessful()) {
                        System.err.println("[AlertManager] Backend error: " + res.code());
                    }
                    res.close();
                }
            });
        } catch (Exception ex) {
            System.err.println("[AlertManager] JSON error: " + ex.getMessage());
        }
    }

    public void stop() {
        running = false;
        // FIX — close the persistent writer when the manager shuts down.
        // Without this the JVM would close it anyway on exit, but being
        // explicit ensures any buffered bytes are flushed before the process ends.
        if (logWriter != null) {
            try {
                logWriter.close();
            } catch (IOException ignored) {}
        }
    }

    public int getTotalAlerts() {
        return totalAlerts;
    }
}