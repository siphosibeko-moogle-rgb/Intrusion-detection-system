package com.ids.core;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Interactive {@code --setup} wizard that writes {@code ids-whitelist.properties}
 * so analysts don't hand-edit it. Self-contained: JDK + Pcap4J only, no new
 * dependencies.
 *
 * <p>Deliberately does NOT prompt for trusted networks / trusted or ignored
 * IPs — {@link com.ids.network.NetworkWhitelist} loads those live from the
 * backend ({@code /api/trusted-networks}, {@code /api/my-whitelist},
 * {@code /api/org-whitelist}), never from this file. Writing them here would
 * silently do nothing.
 */
public class SetupCli {

    private static final String PROPERTIES_FILE = "ids-whitelist.properties";
    private static final Pattern TOKEN_PATTERN   = Pattern.compile("^[A-Za-z0-9_-]+$");
    private static final Pattern IPV4_PATTERN    =
        Pattern.compile("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");

    private final BufferedReader in =
        new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));

    public void run() throws IOException {
        System.out.println("===================================");
        System.out.println(" IDS Sensor Setup");
        System.out.println("===================================");
        System.out.println();

        String orgName    = promptNonBlank("Organization Name: ");
        String sensorName = promptToken("Sensor Name: ");
        String backendUrl = promptBackendUrl("Backend URL [http://localhost:8080]: ");

        String ifaceProperty = promptInterfaceSelection();
        String captureMode   = promptCaptureMode();

        String subnet  = promptSubnet();
        String gateway = promptGateway();

        boolean packetLogging   = promptYesNo("Enable Packet Logging?    (y/N): ");
        boolean forensicLogging = promptYesNo("Enable Forensic Logging?  (y/N): ");
        boolean debugLogging    = promptYesNo("Enable Debug Logging?     (y/N): ");

        System.out.println();
        System.out.println("Note: Trusted networks (CIDR ranges) and trusted/ignored IP addresses are");
        System.out.println("managed live from the dashboard (Trusted Networks / Trusted Devices) and are");
        System.out.println("loaded by the engine from the backend — they are not stored in this file.");

        printSummary(orgName, sensorName, backendUrl, ifaceProperty, captureMode,
            subnet, gateway, packetLogging, forensicLogging, debugLogging);

        Path target = resolveTargetPath();
        if (Files.exists(target)) {
            boolean overwrite = promptYesNo("Config file already exists at " + target.toAbsolutePath()
                + "\nOverwrite existing config? (y/N): ");
            if (!overwrite) {
                System.out.println("Setup cancelled — existing config left untouched.");
                return;
            }
        }

        writeConfig(target, orgName, sensorName, backendUrl, ifaceProperty, captureMode,
            subnet, gateway, packetLogging, forensicLogging, debugLogging);

        printSuccess(target);
    }

    // ── Interface enumeration + selection ──────────────────────────────────

    private String promptInterfaceSelection() throws IOException {
        List<PcapNetworkInterface> devs;
        try {
            devs = Pcaps.findAllDevs();
        } catch (PcapNativeException e) {
            devs = null;
        }
        if (devs == null || devs.isEmpty()) {
            return handleEnumerationFailure();
        }

        System.out.println();
        System.out.println("Available Network Interfaces");
        for (int i = 0; i < devs.size(); i++) {
            PcapNetworkInterface dev = devs.get(i);
            String addrs = dev.getAddresses().stream()
                .filter(a -> a.getAddress() != null)
                .map(a -> a.getAddress().getHostAddress())
                .collect(Collectors.joining(", "));
            System.out.printf("  [%d] %-12s%s%n", i + 1, dev.getName(), addrs);
        }

        while (true) {
            System.out.print("Select interface(s) (comma-separated numbers, or 'all') [all]: ");
            String line = readLine().trim();
            if (line.isEmpty() || line.equalsIgnoreCase("all")) {
                return ""; // empty = auto-discover, NOT the literal "all"
            }

            List<String> names = new ArrayList<>();
            boolean valid = true;
            for (String part : line.split(",")) {
                String trimmed = part.trim();
                int idx;
                try {
                    idx = Integer.parseInt(trimmed);
                } catch (NumberFormatException e) {
                    System.out.println("  '" + trimmed + "' is not a number.");
                    valid = false;
                    break;
                }
                if (idx < 1 || idx > devs.size()) {
                    System.out.println("  " + idx + " is out of range (1-" + devs.size() + ").");
                    valid = false;
                    break;
                }
                names.add(devs.get(idx - 1).getName());
            }
            if (valid && !names.isEmpty()) {
                return String.join(",", names);
            }
        }
    }

    private String handleEnumerationFailure() throws IOException {
        System.out.println();
        System.out.println("Could not enumerate network interfaces — this usually means the process");
        System.out.println("lacks capture privileges (root/Npcap) or libpcap/Npcap isn't installed.");
        System.out.println("  Linux/macOS: re-run with sudo.");
        System.out.println("  Windows: re-run as Administrator (and confirm Npcap is installed).");
        System.out.println();
        while (true) {
            System.out.print("Type an interface name to use manually, or press Enter to exit: ");
            String manual = readLine().trim();
            if (manual.isEmpty()) {
                System.out.println("Exiting setup.");
                System.exit(1);
            }
            return manual;
        }
    }

    // ── Prompts ─────────────────────────────────────────────────────────────

    private String promptNonBlank(String label) throws IOException {
        while (true) {
            System.out.print(label);
            String line = readLine().trim();
            if (!line.isEmpty()) return line;
            System.out.println("  Value cannot be blank.");
        }
    }

    private String promptToken(String label) throws IOException {
        while (true) {
            System.out.print(label);
            String line = readLine().trim();
            if (line.isEmpty()) {
                System.out.println("  Sensor name cannot be blank.");
                continue;
            }
            if (!TOKEN_PATTERN.matcher(line).matches()) {
                System.out.println("  Invalid sensor name — use only letters, digits, '-', '_'.");
                continue;
            }
            return line;
        }
    }

    private String promptBackendUrl(String label) throws IOException {
        while (true) {
            System.out.print(label);
            String line = readLine().trim();
            if (line.isEmpty()) return "http://localhost:8080";
            if (!line.startsWith("http://") && !line.startsWith("https://")) {
                System.out.println("  Backend URL must start with http:// or https://");
                continue;
            }
            try {
                URI uri = URI.create(line);
                if (uri.getHost() == null) {
                    System.out.println("  Not a valid URL — missing host.");
                    continue;
                }
            } catch (IllegalArgumentException e) {
                System.out.println("  Not a valid URL: " + e.getMessage());
                continue;
            }
            return line;
        }
    }

    private String promptCaptureMode() throws IOException {
        System.out.println();
        System.out.println("Capture Mode");
        System.out.println("  [1] Promiscuous");
        System.out.println("  [2] Normal");
        while (true) {
            System.out.print("Select [1]: ");
            String line = readLine().trim();
            if (line.isEmpty() || line.equals("1")) return "PROMISCUOUS";
            if (line.equals("2")) return "NORMAL";
            System.out.println("  Enter 1 or 2.");
        }
    }

    private String promptSubnet() throws IOException {
        System.out.println();
        while (true) {
            System.out.print("Local subnet (CIDR, e.g. 192.168.1.0/24): ");
            String line = readLine().trim();
            if (line.isEmpty()) {
                System.out.println("  Warning: no subnet set — isInternal() will treat ALL traffic as");
                System.out.println("  external until network.subnet is configured.");
                return "";
            }
            if (isValidCidr(line)) return line;
            System.out.println("  Not a valid CIDR (expected a.b.c.d/n, n 0-32).");
        }
    }

    private String promptGateway() throws IOException {
        while (true) {
            System.out.print("Default gateway IP (optional, blank to skip): ");
            String line = readLine().trim();
            if (line.isEmpty()) return "";
            if (isValidIpv4(line)) return line;
            System.out.println("  Not a valid IPv4 address.");
        }
    }

    private boolean promptYesNo(String label) throws IOException {
        System.out.print(label);
        String line = readLine().trim().toLowerCase();
        return line.equals("y") || line.equals("yes");
    }

    private String readLine() throws IOException {
        String line = in.readLine();
        if (line == null) {
            System.out.println();
            System.out.println("Input closed — aborting setup.");
            System.exit(1);
        }
        return line;
    }

    // ── Validation ──────────────────────────────────────────────────────────

    private boolean isValidCidr(String s) {
        int slash = s.indexOf('/');
        if (slash < 0) return false;
        String ip     = s.substring(0, slash);
        String prefix = s.substring(slash + 1);
        if (!isValidIpv4(ip)) return false;
        try {
            int n = Integer.parseInt(prefix);
            return n >= 0 && n <= 32;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private boolean isValidIpv4(String ip) {
        Matcher m = IPV4_PATTERN.matcher(ip);
        if (!m.matches()) return false;
        for (int i = 1; i <= 4; i++) {
            int octet = Integer.parseInt(m.group(i));
            if (octet < 0 || octet > 255) return false;
        }
        return true;
    }

    // ── Summary / file writing ─────────────────────────────────────────────

    private void printSummary(String orgName, String sensorName, String backendUrl,
            String ifaceProperty, String captureMode, String subnet, String gateway,
            boolean packetLogging, boolean forensicLogging, boolean debugLogging) {
        System.out.println();
        System.out.println("Summary");
        System.out.println("-------");
        System.out.println("Organization:      " + orgName);
        System.out.println("Sensor name:       " + sensorName);
        System.out.println("Backend URL:       " + backendUrl);
        System.out.println("Interfaces:        " + (ifaceProperty.isEmpty() ? "(auto-discover)" : ifaceProperty));
        System.out.println("Capture mode:      " + captureMode);
        System.out.println("Subnet:            " + (subnet.isEmpty() ? "(not set)" : subnet));
        System.out.println("Gateway:           " + (gateway.isEmpty() ? "(not set)" : gateway));
        System.out.println("Packet logging:    " + packetLogging);
        System.out.println("Forensic logging:  " + forensicLogging);
        System.out.println("Debug logging:     " + debugLogging);
        System.out.println();
    }

    /** Directory containing the running jar, or CWD if that can't be resolved. */
    private Path resolveTargetPath() {
        try {
            java.net.URL loc = SetupCli.class.getProtectionDomain().getCodeSource().getLocation();
            Path location = Paths.get(loc.toURI());
            Path dir = Files.isDirectory(location) ? location : location.getParent();
            if (dir != null) return dir.resolve(PROPERTIES_FILE);
        } catch (Exception ignored) {
            // Falls through to CWD below.
        }
        return Paths.get(PROPERTIES_FILE).toAbsolutePath();
    }

    private void writeConfig(Path target, String orgName, String sensorName, String backendUrl,
            String ifaceProperty, String captureMode, String subnet, String gateway,
            boolean packetLogging, boolean forensicLogging, boolean debugLogging) throws IOException {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        StringBuilder sb = new StringBuilder();
        sb.append("# ids-whitelist.properties\n");
        sb.append("# Generated by `java -jar ids-engine.jar --setup` on ").append(timestamp).append('\n');
        sb.append('\n');
        sb.append("# Sensor identity\n");
        sb.append("ids.org.name=").append(orgName).append('\n');
        sb.append("ids.sensor.name=").append(sensorName).append('\n');
        sb.append("ids.backend.url=").append(backendUrl).append('\n');
        sb.append('\n');
        sb.append("# Capture\n");
        sb.append("ids.capture.interfaces=").append(ifaceProperty).append('\n');
        sb.append("capture.mode=").append(captureMode).append('\n');
        sb.append('\n');
        sb.append("# Network\n");
        sb.append("network.subnet=").append(subnet).append('\n');
        sb.append("network.gateway=").append(gateway).append('\n');
        sb.append('\n');
        sb.append("# Logging\n");
        sb.append("logging.packet.enabled=").append(packetLogging).append('\n');
        sb.append("logging.forensic.enabled=").append(forensicLogging).append('\n');
        sb.append("logging.debug.enabled=").append(debugLogging).append('\n');
        sb.append('\n');
        sb.append("# Trusted networks (CIDR ranges) and trusted/ignored IP addresses are\n");
        sb.append("# managed live from the dashboard and loaded from the backend — not stored here.\n");

        Files.writeString(target, sb.toString(), StandardCharsets.UTF_8);
    }

    private void printSuccess(Path target) {
        System.out.println();
        System.out.println("Configuration saved to: " + target.toAbsolutePath());
        System.out.println();

        String pass = System.getenv("IDS_ENGINE_PASS");
        if (pass == null || pass.isBlank()) {
            System.out.println("Reminder: set engine credentials before starting (not stored in config):");
            System.out.println("  export IDS_ENGINE_USER=admin        # optional, defaults to admin");
            System.out.println("  export IDS_ENGINE_PASS=your-password");
            System.out.println();
        }

        System.out.println("Start the IDS Engine using:");
        System.out.println("  java -jar ids-engine.jar");
    }
}
