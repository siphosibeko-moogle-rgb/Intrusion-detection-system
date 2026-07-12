package com.ids.config;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Detection-threshold overrides loaded from ids-detection.properties on the
 * classpath. Every detector threshold that matters for false-positive tuning
 * reads through here:
 *
 *     private static final int SYN_THRESHOLD =
 *         DetectionTuning.getInt("nmap.syn.threshold", 15);
 *
 * The second argument is the built-in default — the value the engine shipped
 * with. If the properties file is absent, or a key is missing, the default
 * applies and behavior is identical to before this class existed. That means
 * thresholds can now be tuned per environment (quiet home LAN vs. noisy
 * office network) WITHOUT recompiling, and a broken/deleted config file can
 * never disable detection — it just reverts to defaults.
 *
 * Invalid values (non-numeric, zero, negative) are rejected loudly and the
 * default is used: a typo in a threshold must never silently turn a detector
 * off or make it hair-triggered.
 *
 * See ids-detection.properties in src/main/resources for the full key list
 * with documentation.
 */
public final class DetectionTuning {

    private static final Properties PROPS = load();

    private DetectionTuning() {}

    private static Properties load() {
        Properties p = new Properties();
        try (InputStream in = DetectionTuning.class.getClassLoader()
                .getResourceAsStream("ids-detection.properties")) {
            if (in == null) {
                System.out.println("[DetectionTuning] ids-detection.properties "
                    + "not found — using built-in default thresholds.");
                return p;
            }
            p.load(in);
            System.out.println("[DetectionTuning] Loaded ids-detection.properties ("
                + p.size() + " threshold override" + (p.size() == 1 ? "" : "s") + ").");
        } catch (IOException e) {
            System.err.println("[DetectionTuning] Could not read "
                + "ids-detection.properties (" + e.getMessage()
                + ") — using built-in default thresholds.");
        }
        return p;
    }

    public static int getInt(String key, int defaultValue) {
        return (int) getLong(key, defaultValue);
    }

    public static long getLong(String key, long defaultValue) {
        String raw = PROPS.getProperty(key);
        if (raw == null || raw.isBlank()) return defaultValue;
        try {
            long v = Long.parseLong(raw.trim());
            if (v <= 0) {
                System.err.println("[DetectionTuning] IGNORING " + key + "="
                    + raw.trim() + " — thresholds must be positive. Using default "
                    + defaultValue + ".");
                return defaultValue;
            }
            return v;
        } catch (NumberFormatException e) {
            System.err.println("[DetectionTuning] IGNORING " + key + "='" + raw
                + "' — not a number. Using default " + defaultValue + ".");
            return defaultValue;
        }
    }
}
