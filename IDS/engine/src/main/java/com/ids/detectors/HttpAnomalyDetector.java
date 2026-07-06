package com.ids.detectors;

import com.ids.alerts.AlertManager;
import com.ids.models.PacketContext;
import com.ids.models.ThreatEvent;
import com.ids.models.ThreatEvent.Severity;
import com.ids.models.ThreatEvent.ThreatType;
import com.ids.network.NetworkWhitelist;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Detects HTTP-level anomalies via TCP payload inspection.
 *
 * Checks:
 * 1. HTTP flood — too many requests from one source to one destination in 2s
 * 2. Oversized URI — URI > 2048 bytes (path traversal / overflow attempt)
 * 3. Suspicious verb — TRACE, TRACK, DEBUG (often left open by mistake)
 * 4. Scanner UA — known tool signatures in the User-Agent header
 *
 * Call analyze(ctx, payload) where payload is the reconstructed HTTP request
 * string from the TCP segment. Pass null if unavailable — flood detection
 * still runs on port alone.
 *
 * KNOWN COVERAGE GAP (not fixed here — needs an architecture decision):
 * checks 2-4 require a plaintext HTTP request line. On port 443 (TLS),
 * the reconstructed payload is encrypted bytes, so extractUri/extractHeader
 * never match. In practice this means checks 2-4 only function against
 * plaintext HTTP (port 80/8080/8000) — most modern traffic, including most
 * attack tooling, is HTTPS. Closing this needs either a TLS-terminating
 * proxy in front of protected servers or SNI/cert-level inspection, which
 * is a different and shallower kind of visibility. Flagging, not patching.
 *
 * False positive risks:
 * - FLOOD_THRESHOLD=50/2s used to be keyed by source IP alone, counting
 *   requests to ANY destination. A single busy page load (HTTP/2
 *   multiplexing many sub-requests) or any traffic behind NAT/CGNAT
 *   (multiple real users sharing one visible IP) could trip this with
 *   zero malicious intent. FIX: now keyed by (srcIP, dstIP) — an actual
 *   flood attacker still hammers one target, but this stops unrelated
 *   traffic to different destinations from being summed together.
 * - SCANNER_AGENTS will fire on your OWN authorized security tooling
 *   (Nessus/OpenVAS/Burp run for compliance). FIX: now checks
 *   NetworkWhitelist.isTrustedScanner() before raising HTTP_SCANNER_AGENT.
 */
public class HttpAnomalyDetector implements Detector {

    private static final int FLOOD_THRESHOLD = 50;
    private static final int MAX_URI_LENGTH = 2048;
    private static final long WINDOW_MS = 2_000L;
    private static final long COOLDOWN_MS = 5_000L;

    private static final List<String> SCANNER_AGENTS = List.of(
        "sqlmap", "nikto", "nmap", "masscan", "zgrab",
        "nessus", "openvas", "burpsuite", "dirbuster",
        "gobuster", "wfuzz", "hydra", "metasploit"
    );

    private static final List<String> SUSPICIOUS_VERBS = List.of(
        "TRACE", "TRACK", "DEBUG"
    );

    // FIX: key is now "srcIP:dstIP" instead of just srcIP, so requests to
    // different destinations from the same source (e.g. one NAT gateway,
    // or one host loading many different sites) don't get summed into a
    // single flood count. A real flood — attacker or victim — is still
    // one source hammering one destination, which this still catches.
    private final Map<String, List<Long>> requestLog = new ConcurrentHashMap<>();
    private final Map<String, Long> lastAlerts = new ConcurrentHashMap<>();

    private final AlertManager alertManager;
    // FIX: added so the scanner-UA check can skip known, authorized
    // internal security tools instead of alerting on your own
    // vulnerability-management program every time it runs.
    private final NetworkWhitelist whitelist;

    public HttpAnomalyDetector(AlertManager alertManager, NetworkWhitelist whitelist) {
        this.alertManager = alertManager;
        this.whitelist = whitelist;
    }

    public void analyze(PacketContext ctx, String httpPayload) {

        if (!ctx.isTcp()) return;

        int port = ctx.getDstPort();
        if (port != 80 && port != 8080 && port != 8000 && port != 443) return;

        String srcIP = ctx.getSrcIp();
        String dstIP = ctx.getDstIp();
        String srcMac = ctx.getSrcMac();
        String dstMac = ctx.getDstMac();
        long now = ctx.getTimestamp();

        if (srcIP == null) return;

        // ── 1. FLOOD ────────────────────────────────────────────────────────
        String floodKey = srcIP + ":" + dstIP;
        List<Long> reqs = requestLog.computeIfAbsent(floodKey, k -> new ArrayList<>());
        synchronized (reqs) {
            reqs.add(now);
            reqs.removeIf(t -> (now - t) > WINDOW_MS);

            if (reqs.size() >= FLOOD_THRESHOLD) {
                raise("FLOOD:" + floodKey, ThreatType.HTTP_FLOOD,
                    srcIP, srcMac, dstIP, dstMac, reqs.size(), now,
                    "HTTP flood: " + reqs.size() + " req/2s from " + srcIP + " to " + dstIP,
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
        if (whitelist.isTrustedScanner(srcIP)) return;

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
        String lower = payload.toLowerCase();
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