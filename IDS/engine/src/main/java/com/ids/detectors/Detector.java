package com.ids.detectors;

import com.ids.models.PacketContext;

/**
 * Contract that every IDS detector must implement.
 *
 * Why this exists:
 *   IDSEngine used to call each detector by name — first for cleanup()
 *   (17 separate lines), then for analyze() (18 hand-wired calls in
 *   process(), across four different ad-hoc signatures). Every new
 *   detector meant editing the engine in multiple places.
 *
 *   With this interface, IDSEngine holds a List<Detector> and iterates it
 *   for both dispatch and cleanup. Adding a new detector = one add() line.
 *
 * Payloads:
 *   analyze() implementations that need packet payloads read them off the
 *   context (getUdpPayload()/getHttpPayload()) — the engine extracts each
 *   payload once per packet before dispatch. Payloads are null whenever
 *   absent or not applicable; detectors must null-check.
 *
 * Self-gating:
 *   analyze() is called for every non-ARP packet that passes the whitelist
 *   gate, regardless of protocol. Each detector filters for its own traffic
 *   (protocol, ports) and returns early on everything else — protocol
 *   routing does NOT live in the engine.
 *
 * Future use:
 *   You can add more lifecycle methods here as the system grows:
 *     void onConfigUpdate(DetectorConfig config);
 *     DetectorStats getStats();
 *     boolean isEnabled();
 */
public interface Detector {

    /**
     * Called on a drain-worker thread for every captured non-ARP packet
     * that passed the whitelist gate. Implementations must be thread-safe:
     * multiple drain workers dispatch concurrently.
     */
    void analyze(PacketContext ctx);

    /**
     * Called every 5 minutes by the engine scheduler.
     * Each detector uses this to evict stale per-IP state from its maps,
     * preventing unbounded memory growth.
     */
    void cleanup();
}
