package com.ids.detectors;

/**
 * Contract that every IDS detector must implement.
 *
 * Why this exists:
 *   IDSEngine used to call cleanup() on each detector by name — 17 separate
 *   lines. Every time a new detector was added, three places needed updating:
 *   the field declaration, the initialization in start(), and the cleanup loop.
 *
 *   With this interface, IDSEngine holds a List<Detector>. Adding a new
 *   detector = one line. Cleanup iterates the list automatically.
 *
 * Future use:
 *   You can add more lifecycle methods here as the system grows:
 *     void onConfigUpdate(DetectorConfig config);
 *     DetectorStats getStats();
 *     boolean isEnabled();
 */
public interface Detector {

    /**
     * Called every 5 minutes by the engine scheduler.
     * Each detector uses this to evict stale per-IP state from its maps,
     * preventing unbounded memory growth.
     */
    void cleanup();
}