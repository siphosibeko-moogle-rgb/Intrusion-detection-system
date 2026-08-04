package com.ids.desktop.service;

import java.util.List;
import java.util.Map;

/**
 * Immutable snapshot returned by {@link EngineConfigClient#fetchConfig()}:
 * the engine's current {@code ids.capture.interfaces} value, the interfaces
 * actually present on the engine host, and the current value of every
 * structured settings key from {@code ids-whitelist.properties}.
 *
 * This mirrors the engine's {@code GET /engine/config} payload; it is NOT a
 * backend/DB entity, which is why it lives next to EngineConfigClient rather
 * than in the model package with the backend-backed items.
 */
public class EngineConfig {

    /** One host interface: device name + first IP (null when it has none). */
    public static final class HostInterface {
        private final String name;
        private final String ip;
        public HostInterface(String name, String ip) {
            this.name = name;
            this.ip   = ip;
        }
        public String getName() { return name; }
        public String getIp()   { return ip; }
    }

    private final String captureInterfaces;
    private final List<HostInterface> hostInterfaces;
    // Map<String,String> rather than typed getters: the allowed-key set
    // lives server-side (EngineConfigServer.ALLOWED_SETTINGS_KEYS) and is
    // echoed verbatim in the "settings" JSON object; mirroring it here as a
    // map means a key added/renamed on the engine side doesn't also require
    // a new getter here — the panel manager binds fields by the same key
    // strings it POSTs back. Immutable (Map.copyOf) to match the rest of
    // this class.
    private final Map<String, String> settings;

    public EngineConfig(String captureInterfaces, List<HostInterface> hostInterfaces,
                         Map<String, String> settings) {
        this.captureInterfaces = captureInterfaces;
        this.hostInterfaces    = hostInterfaces;
        this.settings           = Map.copyOf(settings);
    }

    /** Current {@code ids.capture.interfaces} value; "" means auto-discover. */
    public String getCaptureInterfaces() { return captureInterfaces; }

    public List<HostInterface> getHostInterfaces() { return hostInterfaces; }

    /**
     * Current value of each allowed structured settings key (e.g.
     * {@code network.subnet}, {@code capture.mode}); "" when the key is
     * absent from the engine's properties file. Keys match exactly what
     * {@link EngineConfigClient#saveSettings} expects back.
     */
    public Map<String, String> getSettings() { return settings; }
}
