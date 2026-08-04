package com.ids.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.ids.network.CidrMatcher;
import com.ids.network.NetworkWhitelist;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Host-local HTTP endpoint for reading/writing a small, fixed set of keys in
 * the engine's own {@code ids-whitelist.properties} — the
 * {@code ids.capture.interfaces} line (owned by the desktop's interface
 * checkbox UI) plus a structured set of network/capture settings (owned by
 * the desktop's settings form) — so the co-located desktop client can edit
 * host-local engine config without reaching into a filesystem it can't see.
 *
 * <p>This is a STRUCTURED editor, not a raw file editor: only the keys in
 * {@link #ALLOWED_SETTINGS_KEYS} (plus {@link #KEY}) may ever be read or
 * written. Every other line in the file — comments, unrelated keys — passes
 * through a write untouched.
 *
 * <p>Two verbs on one path:
 * <ul>
 *   <li>{@code GET  /engine/config} — current {@code ids.capture.interfaces}
 *       value, the interfaces actually present on this host, and the current
 *       value of every allowed settings key.</li>
 *   <li>{@code POST /engine/config} — validate + persist {@code captureInterfaces}
 *       and/or {@code settings}, then report {@code restartRequired:true}.</li>
 * </ul>
 *
 * <p>The engine parses this file <b>once at startup</b> ({@link NetworkWhitelist}).
 * Writing it does NOT take effect until the engine restarts — reopening pcap
 * handles or re-reading whitelist rules at runtime is deliberately out of
 * scope — so every write response carries {@code restartRequired:true} to make
 * that explicit to the UI.
 *
 * <p><b>Loopback-only by design.</b> This endpoint writes to a local file. If it
 * were reachable off-box it would be a remote-config attack surface (rewrite the
 * capture interfaces to a dead NIC, or the trusted subnet to something useless,
 * and the engine goes blind/miscalibrated after the next restart). It binds to
 * {@code 127.0.0.1} only and is never exposed beyond the host.
 */
public class EngineConfigServer {

    private static final String BIND_ADDR = "127.0.0.1";
    static final int PORT = 9091;
    private static final String PATH = "/engine/config";

    /** Sole owner: the desktop's capture-interface checkbox UI. */
    private static final String KEY  = "ids.capture.interfaces";

    /**
     * The fixed, explicit set of keys the structured settings form may read
     * or write. Anything not in this set is rejected — never read, never
     * written. Deliberately excludes {@code ids.capture.interfaces} (owned by
     * the checkbox UI above, one writer per key) and {@code ids.backend.url}
     * (changing it mid-run would break the engine's own backend connection;
     * that belongs to {@code --setup}).
     */
    private static final List<String> ALLOWED_SETTINGS_KEYS = List.of(
        "network.subnet",
        "network.gateway",
        "network.docker.subnets",
        "network.trusted.scanners",
        "network.beacon.trusted.destinations",
        "network.dhcp.trusted.servers",
        "capture.mode"
    );

    // Mirrors NetworkWhitelist.MAC_PATTERN exactly (loose but effective: 6
    // groups of 2 hex chars, separated by ':' or '-'). Duplicated here rather
    // than exposed from NetworkWhitelist so that class's parser stays the
    // single source of truth for engine behavior while this validator stays
    // a read-only mirror of it — see class javadoc.
    private static final java.util.regex.Pattern MAC_PATTERN =
        java.util.regex.Pattern.compile("^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$");

    private final ObjectMapper mapper;
    private HttpServer server;

    public EngineConfigServer(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    /** Starts the listener on a daemon-backed executor so it never blocks JVM shutdown. */
    public void start() throws IOException {
        // Bind explicitly to loopback — NOT the wildcard address. See class javadoc.
        server = HttpServer.create(new InetSocketAddress(InetAddress.getByName(BIND_ADDR), PORT), 0);
        server.createContext(PATH, this::handle);
        // Daemon threads: the config listener must not keep the JVM alive on shutdown.
        java.util.concurrent.ThreadFactory daemonFactory = r -> {
            Thread t = new Thread(r, "engine-config");
            t.setDaemon(true);
            return t;
        };
        server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool(daemonFactory));
        server.start();
        System.out.println("[IDS] Config endpoint listening on http://" + BIND_ADDR + ":" + PORT + PATH
            + " (loopback only)");
    }

    /** Stops the listener; safe to call when never started. */
    public void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    // ── Request routing ────────────────────────────────────────────────────

    private void handle(HttpExchange ex) throws IOException {
        try {
            switch (ex.getRequestMethod()) {
                case "GET":  handleGet(ex);  break;
                case "POST": handlePost(ex); break;
                default:     sendError(ex, 405, "Method not allowed: " + ex.getRequestMethod());
            }
        } catch (ConfigException ce) {
            sendError(ex, ce.status, ce.getMessage());
        } catch (Exception e) {
            // Fail loudly — never silently no-op on a config read/write.
            sendError(ex, 500, e.getClass().getSimpleName() + ": " + e.getMessage());
        } finally {
            ex.close();
        }
    }

    private void handleGet(HttpExchange ex) throws IOException, ConfigException {
        Path file = resolveConfigFile();

        List<String> allKeys = new ArrayList<>(ALLOWED_SETTINGS_KEYS);
        allKeys.add(KEY);
        Map<String, String> values = readValues(file, allKeys);

        ObjectNode out = mapper.createObjectNode();
        out.put("captureInterfaces", values.get(KEY));
        out.put("restartRequired", false);
        out.put("configFile", file.toString());

        ArrayNode ifaces = out.putArray("hostInterfaces");
        for (PcapNetworkInterface dev : findAllDevs()) {
            ObjectNode n = ifaces.addObject();
            n.put("name", dev.getName());
            n.put("ip", firstIp(dev)); // null when the interface has no IP
        }

        ObjectNode settings = out.putObject("settings");
        for (String k : ALLOWED_SETTINGS_KEYS) {
            settings.put(k, values.get(k)); // blank when the key is absent
        }

        sendJson(ex, 200, out);
    }

    private void handlePost(HttpExchange ex) throws IOException, ConfigException {
        byte[] body = ex.getRequestBody().readAllBytes();
        JsonNode root;
        try {
            root = mapper.readTree(body);
        } catch (Exception e) {
            throw new ConfigException(400, "Request body is not valid JSON");
        }
        boolean hasCapture  = root != null && root.hasNonNull("captureInterfaces");
        boolean hasSettings = root != null && root.hasNonNull("settings");
        if (!hasCapture && !hasSettings) {
            throw new ConfigException(400,
                "Provide at least one of: captureInterfaces, settings");
        }

        // Validate everything BEFORE writing anything — a body with both
        // fields is all-or-nothing: one bad value must leave the file
        // completely unchanged, not half-applied.
        Map<String, String> edits = new LinkedHashMap<>();

        if (hasCapture) {
            edits.put(KEY, validateCaptureInterfaces(root.get("captureInterfaces").asText()));
        }

        if (hasSettings) {
            JsonNode settingsNode = root.get("settings");
            if (!settingsNode.isObject()) {
                throw new ConfigException(400, "settings must be a JSON object");
            }
            // Reject any unknown key before validating/writing anything else.
            Iterator<String> fieldNames = settingsNode.fieldNames();
            while (fieldNames.hasNext()) {
                String key = fieldNames.next();
                if (!ALLOWED_SETTINGS_KEYS.contains(key)) {
                    throw new ConfigException(400, "Unknown settings key: " + key);
                }
            }
            for (String key : ALLOWED_SETTINGS_KEYS) {
                if (!settingsNode.has(key)) continue;
                String raw = settingsNode.get(key).isNull() ? "" : settingsNode.get(key).asText("");
                // null == "leave this key absent" (blank/omit); non-null (possibly "")
                // == "write this value". See validateSetting() per-key.
                edits.put(key, validateSetting(key, raw));
            }
        }

        applyEdits(resolveConfigFile(), edits);

        ObjectNode out = mapper.createObjectNode();
        out.put("saved", true);
        out.put("restartRequired", true);
        sendJson(ex, 200, out);
    }

    // ── captureInterfaces validation (unchanged behavior) ─────────────────────

    /**
     * Splits on comma, trims, drops blanks, and rejects any name not
     * physically present on the host. Silently accepting a typo means the
     * engine captures nothing after restart — the exact fail-silently trap
     * this endpoint exists to prevent. Returns the canonical comma-joined
     * value (never null — an empty list means "auto-discover" and is written
     * as an explicit empty value, matching prior behavior).
     */
    private String validateCaptureInterfaces(String raw) throws ConfigException {
        List<String> requested = new ArrayList<>();
        for (String part : raw.split(",")) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) requested.add(trimmed);
        }

        List<String> hostNames = new ArrayList<>();
        for (PcapNetworkInterface dev : findAllDevs()) hostNames.add(dev.getName());
        List<String> unknown = new ArrayList<>();
        for (String name : requested) {
            if (hostNames.stream().noneMatch(h -> h.equalsIgnoreCase(name))) {
                unknown.add(name);
            }
        }
        if (!unknown.isEmpty()) {
            throw new ConfigException(400,
                "Unknown interface(s) not present on host: " + String.join(", ", unknown)
                + ". Present: " + String.join(", ", hostNames));
        }
        return String.join(",", requested);
    }

    // ── Structured settings validation (mirrors NetworkWhitelist.loadProperties) ─

    /**
     * Validates one settings value per the rule table for {@code key},
     * mirroring exactly what {@link NetworkWhitelist#loadProperties()} does
     * with the same key so this endpoint never accepts a value the engine
     * would reject/ignore at load time.
     *
     * @return the canonical value to write, or {@code null} meaning "leave
     *         this key absent" (blank input for an optional key) — callers
     *         pass this straight to {@link #applyEdits}, which removes/omits
     *         the key's line when the value is null.
     */
    private String validateSetting(String key, String raw) throws ConfigException {
        String value = raw == null ? "" : raw.trim();
        switch (key) {
            case "network.subnet":
                return value.isEmpty() ? null : validateSubnetEntry(key, value);
            case "network.gateway":
                return value.isEmpty() ? null : validateIpv4(key, value);
            case "network.docker.subnets":
                return validateList(key, value, this::validateSubnetEntry);
            case "network.trusted.scanners":
            case "network.beacon.trusted.destinations":
                return validateList(key, value, this::validateIpv4);
            case "network.dhcp.trusted.servers":
                return validateList(key, value, this::validateMac);
            case "capture.mode":
                return value.isEmpty() ? null : validateCaptureMode(key, value);
            default:
                // Unreachable: handlePost already rejects unknown keys.
                throw new ConfigException(400, "Unknown settings key: " + key);
        }
    }

    @FunctionalInterface
    private interface ElementValidator {
        String validate(String key, String element) throws ConfigException;
    }

    /**
     * Comma-list validation shared by every list-shaped key: trim elements,
     * drop blanks (matches NetworkWhitelist's own parsing), then validate
     * every surviving element with {@code elementValidator}. Unlike the
     * engine's own loader — which silently drops a malformed DHCP MAC and
     * keeps going — this rejects the WHOLE save on the first bad element, so
     * the user is told their input was wrong instead of it vanishing quietly.
     * Returns null (omit the key) when the list ends up empty.
     */
    private String validateList(String key, String raw, ElementValidator elementValidator)
            throws ConfigException {
        if (raw.isEmpty()) return null;
        List<String> out = new ArrayList<>();
        for (String part : raw.split(",")) {
            String t = part.trim();
            if (t.isEmpty()) continue;
            out.add(elementValidator.validate(key, t));
        }
        return out.isEmpty() ? null : String.join(",", out);
    }

    /**
     * A subnet-entry element accepts two forms, mirroring
     * NetworkWhitelist.matchesSubnetEntry() exactly: an IPv4 CIDR
     * ("192.168.8.0/24"), validated via CidrMatcher.parse(); or a legacy
     * dotted prefix ("192.168.8."), which the engine matches with a raw
     * String.startsWith() and therefore never format-checks beyond
     * non-blank. We mirror that leniency rather than inventing a stricter
     * rule the engine itself doesn't enforce.
     */
    private String validateSubnetEntry(String key, String entry) throws ConfigException {
        if (entry.contains("/")) {
            if (CidrMatcher.parse(entry) == null) {
                throw new ConfigException(400, key + ": invalid CIDR '" + entry + "'");
            }
        }
        return entry;
    }

    /** IPv4 dotted-quad, 4 octets 0-255 — reuses CidrMatcher's own parser. */
    private String validateIpv4(String key, String value) throws ConfigException {
        if (CidrMatcher.ipv4ToLong(value) < 0) {
            throw new ConfigException(400, key + ": invalid IPv4 address '" + value + "'");
        }
        return value;
    }

    /** Matches NetworkWhitelist.MAC_PATTERN; canonicalized to lowercase (same as the engine). */
    private String validateMac(String key, String value) throws ConfigException {
        String lower = value.toLowerCase();
        if (!MAC_PATTERN.matcher(lower).matches()) {
            throw new ConfigException(400,
                key + ": invalid MAC address '" + value + "' (expected aa:bb:cc:dd:ee:ff)");
        }
        return lower;
    }

    /** PROMISCUOUS | NORMAL, case-insensitive in, canonical uppercase out. */
    private String validateCaptureMode(String key, String value) throws ConfigException {
        String upper = value.toUpperCase();
        if (!upper.equals("PROMISCUOUS") && !upper.equals("NORMAL")) {
            throw new ConfigException(400,
                key + ": must be PROMISCUOUS or NORMAL, got '" + value + "'");
        }
        return upper;
    }

    // ── File path resolution (shared with NetworkWhitelist) ──────────────────

    /**
     * Resolves the same external {@code ids-whitelist.properties} location
     * {@link NetworkWhitelist#resolveExternalPropertiesPath()} prefers at
     * startup — next to the running jar, or the exploded classes directory in
     * dev — as a writable filesystem Path. Both sides resolving the same way
     * is what makes a write here actually take effect on the next engine
     * restart, including when running as a packaged jar (Docker): the file
     * need not already exist yet (first boot before any {@code --setup} run);
     * {@link #handleGet} and {@link #handlePost} both treat a missing file as
     * "not configured yet" rather than an error.
     */
    private Path resolveConfigFile() throws ConfigException {
        Path path = NetworkWhitelist.resolveExternalPropertiesPath();
        if (path == null) {
            throw new ConfigException(500,
                "Cannot resolve a filesystem location for " + NetworkWhitelist.PROPERTIES_RESOURCE
                + " next to the running jar/classes.");
        }
        return path;
    }

    /**
     * Reads the current raw (un-parsed, un-split) right-hand-side value of
     * each requested key in one pass over the file. A key absent from the
     * file maps to {@code ""} — "not configured" — never null, so GET
     * responses and downstream form fields never have to null-check.
     */
    private Map<String, String> readValues(Path file, List<String> keys) throws ConfigException {
        Map<String, String> out = new LinkedHashMap<>();
        for (String k : keys) out.put(k, "");
        if (!Files.exists(file)) return out;
        try {
            Set<String> keySet = Set.copyOf(keys);
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                String k = activeKeyOf(line, keySet);
                if (k != null) {
                    int eq = line.indexOf('=');
                    out.put(k, eq < 0 ? "" : line.substring(eq + 1).trim());
                }
            }
            return out;
        } catch (IOException e) {
            throw new ConfigException(500, "Cannot read " + file + ": " + e.getMessage());
        }
    }

    /**
     * Applies a {@code key -> value} map to the properties file in a SINGLE
     * atomic write: for each key present in {@code edits}, its active
     * (non-comment) line is replaced if found, else the key is appended; a
     * {@code null} value means "leave this key absent" (its line is removed
     * if present, and it is never appended). Every other line — comments,
     * unrelated keys — passes through byte-for-byte untouched. Written to a
     * temp file in the same directory then moved into place with
     * ATOMIC_MOVE — a crash mid-write can never leave a truncated/empty
     * config, and N keys changed in one call means exactly one move, never N.
     */
    private void applyEdits(Path file, Map<String, String> edits) throws ConfigException {
        try {
            // Operate on the raw text (not Files.readAllLines, which loses the
            // terminator style) so every unchanged byte survives round-trip.
            // The file is LF; we split/join on '\n' to stay deterministic
            // regardless of the host's platform line separator.
            // Missing file (first boot before any --setup run, or a jar
            // deployment with nothing written next to it yet) starts as an
            // empty document — keys get appended fresh below.
            String content = Files.exists(file) ? Files.readString(file, StandardCharsets.UTF_8) : "";
            boolean trailingNewline = content.endsWith("\n");
            String[] lines = content.split("\n", -1); // -1 keeps a trailing empty segment
            // When there is a trailing newline, split(...,-1) yields a final
            // empty segment we must not treat as a real line.
            int realLines = trailingNewline ? lines.length - 1 : lines.length;

            Set<String> applied = new java.util.HashSet<>();
            List<String> outLines = new ArrayList<>();
            for (int i = 0; i < realLines; i++) {
                String line = lines[i];
                String key = activeKeyOf(line, edits.keySet());
                if (key != null) {
                    applied.add(key);
                    String newValue = edits.get(key);
                    if (newValue == null) {
                        continue; // omit: drop this line entirely
                    }
                    outLines.add(key + "=" + newValue);
                } else {
                    outLines.add(line);
                }
            }
            // Append any edited key that wasn't already present in the file
            // (skip null values — nothing to append for "leave absent").
            for (String key : edits.keySet()) {
                String newValue = edits.get(key);
                if (!applied.contains(key) && newValue != null) {
                    outLines.add(key + "=" + newValue);
                }
            }

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < outLines.size(); i++) {
                sb.append(outLines.get(i));
                if (i < outLines.size() - 1) sb.append('\n');
            }
            if (trailingNewline) sb.append('\n');

            // Atomic write: temp file in the same dir, then ATOMIC_MOVE. Never
            // truncate-in-place — a crash mid-write must not leave an empty config.
            Path dir = file.toAbsolutePath().getParent();
            Path tmp = Files.createTempFile(dir, ".ids-whitelist", ".tmp");
            try {
                Files.writeString(tmp, sb.toString(), StandardCharsets.UTF_8);
                Files.move(tmp, file,
                    StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (IOException moveErr) {
                Files.deleteIfExists(tmp); // don't leak the temp file on failure
                throw moveErr;
            }
        } catch (IOException e) {
            throw new ConfigException(500, "Cannot write " + file + ": " + e.getMessage());
        }
    }

    /** The key name this line actively assigns (not a comment), if it's one of {@code keys}; else null. */
    private String activeKeyOf(String line, Set<String> keys) {
        String t = line.trim();
        if (t.startsWith("#") || t.startsWith("!")) return null; // properties comment markers
        int eq = t.indexOf('=');
        if (eq < 0) return null;
        String k = t.substring(0, eq).trim();
        return keys.contains(k) ? k : null;
    }

    // ── Pcap helpers ────────────────────────────────────────────────────────

    private List<PcapNetworkInterface> findAllDevs() throws ConfigException {
        try {
            List<PcapNetworkInterface> devs = Pcaps.findAllDevs();
            return devs == null ? new ArrayList<>() : devs;
        } catch (Exception e) {
            throw new ConfigException(500, "Cannot enumerate host interfaces: " + e.getMessage());
        }
    }

    private String firstIp(PcapNetworkInterface dev) {
        for (PcapAddress addr : dev.getAddresses()) {
            if (addr.getAddress() != null) return addr.getAddress().getHostAddress();
        }
        return null;
    }

    // ── HTTP response helpers ────────────────────────────────────────────────

    private void sendJson(HttpExchange ex, int status, JsonNode body) throws IOException {
        byte[] bytes = mapper.writeValueAsBytes(body);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    private void sendError(HttpExchange ex, int status, String message) throws IOException {
        ObjectNode err = mapper.createObjectNode();
        err.put("error", message);
        sendJson(ex, status, err);
    }

    /** Carries an intended HTTP status out of the read/write helpers. */
    private static final class ConfigException extends Exception {
        final int status;
        ConfigException(int status, String message) {
            super(message);
            this.status = status;
        }
    }
}
