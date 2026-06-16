package com.ids.detectors;

import com.ids.alerts.AlertManager;
import com.ids.models.PacketContext;
import com.ids.models.ThreatEvent;
import com.ids.models.ThreatEvent.Severity;
import com.ids.models.ThreatEvent.ThreatType;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Detects HTTP-level anomalies via TCP payload inspection.
 *
 * Checks:
 *   1. HTTP flood       — too many requests from one source in 2 s
 *   2. Oversized URI    — URI > 2048 bytes (path traversal / overflow attempt)
 *   3. Suspicious verb  — TRACE, TRACK, DEBUG (often left open by mistake)
 *   4. Scanner UA       — known tool signatures in the User-Agent header
 *
 * Call analyze(ctx, payload) where payload is the reconstructed HTTP request
 * string from the TCP segment. Pass null if unavailable — flood detection
 * still runs on port alone.
 */
public class HttpAnomalyDetector implements Detector {

    private static final int  FLOOD_THRESHOLD = 50;
    private static final int  MAX_URI_LENGTH  = 2048;
    private static final long WINDOW_MS       = 2_000L;
    private static final long COOLDOWN_MS     = 5_000L;

    private static final List<String> SCANNER_AGENTS = List.of(
            "sqlmap", "nikto", "nmap", "masscan", "zgrab",
            "nessus", "openvas", "burpsuite", "dirbuster",
            "gobuster", "wfuzz", "hydra", "metasploit"
    );

    private static final List<String> SUSPICIOUS_VERBS = List.of(
            "TRACE", "TRACK", "DEBUG"
    );

    // per srcIP: request timestamps in current window
    private final Map<String, List<Long>> requestLog = new ConcurrentHashMap<>();
    private final Map<String, Long>       lastAlerts = new ConcurrentHashMap<>();

    private final AlertManager alertManager;

    public HttpAnomalyDetector(AlertManager alertManager) {
        this.alertManager = alertManager;
    }

    public void analyze(PacketContext ctx, String httpPayload) {

        if (!ctx.isTcp()) return;

        int port = ctx.getDstPort();
        if (port != 80 && port != 8080 && port != 8000 && port != 443) return;

        String srcIP  = ctx.getSrcIp();
        String dstIP  = ctx.getDstIp();
        String srcMac = ctx.getSrcMac();
        String dstMac = ctx.getDstMac();
        long   now    = ctx.getTimestamp();

        if (srcIP == null) return;

        // ── 1. FLOOD ────────────────────────────────────────────────────────
        List<Long> reqs = requestLog.computeIfAbsent(srcIP, k -> new ArrayList<>());
        synchronized (reqs) {
            reqs.add(now);
            reqs.removeIf(t -> (now - t) > WINDOW_MS);

            if (reqs.size() >= FLOOD_THRESHOLD) {
                raise("FLOOD:" + srcIP, ThreatType.HTTP_FLOOD,
                        srcIP, srcMac, dstIP, dstMac, reqs.size(), now,
                        "HTTP flood: " + reqs.size() + " req/2s from " + srcIP,
                        Severity.HIGH, port);
            }
        }

        if (httpPayload == null || httpPayload.isEmpty()) return;

        String requestLine = firstLine(httpPayload);

        // ── 2. OVERSIZED URI ────────────────────────────────────────────────
        String uri = extractUri(requestLine);
        if (uri != null && uri.length() > MAX_URI_LENGTH) {
            raise("URI:" + srcIP, ThreatType.HTTP_OVERSIZED_URI,
                    srcIP, srcMac, dstIP, dstMac, 1, now,
                    "Oversized URI (" + uri.length() + " bytes) from " + srcIP,
                    Severity.HIGH, port);
        }

        // ── 3. SUSPICIOUS VERB ──────────────────────────────────────────────
        String upperLine = requestLine.toUpperCase();
        for (String verb : SUSPICIOUS_VERBS) {
            if (upperLine.startsWith(verb + " ")) {
                raise("VERB:" + srcIP + ":" + verb, ThreatType.HTTP_SUSPICIOUS_VERB,
                        srcIP, srcMac, dstIP, dstMac, 1, now,
                        "Suspicious HTTP verb " + verb + " from " + srcIP,
                        Severity.MEDIUM, port);
                break;
            }
        }

        // ── 4. SCANNER USER-AGENT ────────────────────────────────────────────
        String ua = extractHeader(httpPayload, "User-Agent");
        if (ua != null) {
            String uaLower = ua.toLowerCase();
            for (String sig : SCANNER_AGENTS) {
                if (uaLower.contains(sig)) {
                    raise("UA:" + srcIP + ":" + sig, ThreatType.HTTP_SCANNER_AGENT,
                            srcIP, srcMac, dstIP, dstMac, 1, now,
                            "Scanner User-Agent from " + srcIP + ": " + ua,
                            Severity.HIGH, port);
                    break;
                }
            }
        }
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    private void raise(String key, ThreatType type,
                       String srcIP, String srcMac, String dstIP, String dstMac,
                       int count, long now, String details, Severity sev, int port) {
        Long last = lastAlerts.get(key);
        if (last != null && (now - last) < COOLDOWN_MS) return;
        lastAlerts.put(key, now);
        alertManager.raise(new ThreatEvent(
                type, srcIP, srcMac, dstIP, dstMac,
                count, WINDOW_MS, details, sev, "TCP", "HTTP", port
        ));
    }

    private String firstLine(String payload) {
        int idx = payload.indexOf('\n');
        return (idx > 0 ? payload.substring(0, idx) : payload).trim();
    }

    private String extractUri(String requestLine) {
        String[] parts = requestLine.split(" ");
        return parts.length >= 2 ? parts[1] : null;
    }

    private String extractHeader(String payload, String name) {
        String lower  = payload.toLowerCase();
        String needle = name.toLowerCase() + ":";
        int idx = lower.indexOf(needle);
        if (idx < 0) return null;
        int end = payload.indexOf('\n', idx);
        return payload.substring(idx + needle.length(), end < 0 ? payload.length() : end).trim();
    }

    public void cleanup() {
        long now = System.currentTimeMillis();
        requestLog.entrySet().removeIf(e -> {
            synchronized (e.getValue()) {
                e.getValue().removeIf(t -> (now - t) > WINDOW_MS);
                return e.getValue().isEmpty();
            }
        });
        lastAlerts.entrySet().removeIf(e -> (now - e.getValue()) > COOLDOWN_MS * 4);
    }
}