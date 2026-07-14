package com.ids.detectors;

import com.ids.alerts.AlertSink;
import com.ids.models.PacketContext;
import com.ids.models.ThreatEvent;
import com.ids.models.ThreatEvent.Severity;
import com.ids.models.ThreatEvent.ThreatType;
import com.ids.network.NetworkWhitelist;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class WhitelistViolationDetector implements Detector {

	private final AlertSink alertManager;
	private final NetworkWhitelist whitelist;

    private final Map<String, Long> lastAlertTime = new ConcurrentHashMap<>();
    private static final long COOLDOWN_MS  = 60_000L;
    private static final long DEVICE_COOLDOWN_MS  = 3_600_000L; // 1 hour for device alerts

    // Warm-up: learn silently for the first 90 seconds before alerting.
    // This prevents the flood of UNKNOWN_* alerts on startup when the
    // device registry is empty.
    private final long startTime = System.currentTimeMillis();
    private static final long WARMUP_MS = 90_000L;

    public WhitelistViolationDetector(AlertSink alertManager,
                                      NetworkWhitelist whitelist ) {
        this.alertManager      = alertManager;
        this.whitelist         = whitelist;
        
    }

    public void analyze(PacketContext ctx) {
        if (ctx.getSrcIp() == null) return;

        String srcIP  = normalize(ctx.getSrcIp());
        String dstIP  = ctx.getDstIp() != null ? normalize(ctx.getDstIp()) : null;
        String srcMac = ctx.getSrcMac();
        String proto  = ctx.getProtocol();

        // Never alert on system/multicast/broadcast addresses
        if (isSystemAddress(srcIP)) return;
        if (srcMac != null && srcMac.equalsIgnoreCase("ff:ff:ff:ff:ff:ff")) return;

        boolean trusted = whitelist.isTrusted(srcIP);
        boolean approvedOrg = whitelist.isApprovedOrg(srcIP);
        // Curated provider CIDR ranges (trusted_networks table). Scope is
        // deliberately limited to the UNKNOWN_IP/OUTSIDE_SUBNET noise checks
        // in THIS detector — see the note on NetworkWhitelist.isTrustedNetwork().
        boolean trustedNet = whitelist.isTrustedNetwork(srcIP);
        boolean isInternal = whitelist.isInternal(srcIP);
        boolean isExternal  = !isRFC1918(srcIP); // public internet IP
        long    now         = System.currentTimeMillis();
        boolean warmedUp    = (now - startTime) > WARMUP_MS;

        
        if (!warmedUp) {
            System.out.printf("[Whitelist] (warmup, not alerting) seen: %s [%s]%n", srcIP, srcMac);
            return;
        }
       

        // ── UNKNOWN IP ──────────────────────────────────────────────────
        // Only alert on internal IPs we don't recognise.
        // We do NOT alert on external IPs being unknown — the entire
        // internet is "unknown" and that's expected.
        if (isInternal && !trusted && !trustedNet
                && shouldAlert("IP:" + srcIP, now, DEVICE_COOLDOWN_MS)) {
            alertManager.raise(new ThreatEvent(
                ThreatType.UNKNOWN_IP, srcIP, srcMac,
                dstIP, null, 1, 0,
                // LOW, not MEDIUM: a new device on the LAN is common (guest
                // laptops, phones joining wifi) — matches the ARP path below
                // and the UNKNOWN_IP severity floor. Floors only raise, so
                // this call site had to be lowered explicitly.
                "Unknown internal IP: " + srcIP + " [MAC: " + srcMac + "]",
                Severity.LOW, proto, "UNKNOWN", 0
            ));
        }

        // ── UNKNOWN MAC ─────────────────────────────────────────────────
        // Only meaningful for internal devices.
        // A new MAC on your LAN is worth knowing about.
        // An external server's MAC is just your router's MAC anyway (NAT).
        if (isInternal
                && srcMac != null
                && !whitelist.isTrusted(srcIP, srcMac)
                && !srcMac.toLowerCase().startsWith("01:")
                && shouldAlert("MAC:" + srcMac, now)) {
            alertManager.raise(new ThreatEvent(
                ThreatType.UNKNOWN_MAC, srcIP, srcMac,
                dstIP, null, 1, 0,
                // LOW for the same reason as UNKNOWN_IP above.
                "Unknown MAC on LAN: " + srcMac + " (IP: " + srcIP + ")",
                Severity.LOW, proto, "UNKNOWN", 0
            ));
        }

        // ── ROGUE PRIVATE IP ────────────────────────────────────────────
        // This replaces OUTSIDE_SUBNET with something that actually means
        // something: a private RFC1918 address appearing on the wire that
        // does NOT belong to your subnet. 
        //
        // Real example of what this catches:
        //   Your subnet is 192.168.8.x
        //   You see a packet sourced from 10.0.0.5 — that's a different
        //   private range. Could be a misconfigured VPN, a rogue device,
        //   or traffic leaking from another network segment.
        //
        // What it does NOT catch (intentionally):
        //   34.107.221.82 — that's Google. External IPs are expected.
        if (!isExternal          // it IS a private/RFC1918 address
                && !isInternal   // but NOT from your subnet
                && !trusted
                && !trustedNet
                && shouldAlert("ROGUE:" + srcIP, now)) {
            alertManager.raise(new ThreatEvent(
                ThreatType.OUTSIDE_SUBNET, srcIP, srcMac,
                dstIP, null, 1, 0,
                "Rogue private IP (not in your subnet): " + srcIP,
                Severity.HIGH, proto, "ROGUE_IP", 0
            ));
        }
    }

    public void analyzeArp(Packet packet) {
        try {
            ArpPacket arp = packet.get(ArpPacket.class);
            if (arp == null) return;

            String srcIP  = arp.getHeader().getSrcProtocolAddr().getHostAddress();
            String srcMac = arp.getHeader().getSrcHardwareAddr().toString();

            if (isSystemAddress(srcIP)) return;
            if (whitelist.isTrusted(srcIP, srcMac)) return;

            long now = System.currentTimeMillis();
            if ((now - startTime) <= WARMUP_MS) return;

            // `srcIP.startsWith(srcIP)` — a tautology that's always true
            // for every address on every interface (ARP has no subnet filtering
            // at all as a result). Use the same isInternal() check analyze() uses,
            // so ARP alerts respect network.subnet and network.docker.subnets
            // the same way IP-based alerts do.
            boolean isInternal = whitelist.isInternal(srcIP);
            if (isInternal && shouldAlert("ARP:" + srcIP, now)) {
                alertManager.raise(new ThreatEvent(
                    ThreatType.UNKNOWN_IP, srcIP, srcMac,
                    "network", null, 1, 0,
                    "New device via ARP: " + srcIP + " [" + srcMac + "]",
                    Severity.LOW, "ARP", "UNKNOWN", 0
                ));
            }
        } catch (Exception ignored) {}
    }

    private boolean isRFC1918(String ip) {
        return ip.startsWith("10.")
            || ip.startsWith("172.16.")  || ip.startsWith("172.17.")
            || ip.startsWith("172.18.")  || ip.startsWith("172.19.")
            || ip.startsWith("172.20.")  || ip.startsWith("172.21.")
            || ip.startsWith("172.22.")  || ip.startsWith("172.23.")
            || ip.startsWith("172.24.")  || ip.startsWith("172.25.")
            || ip.startsWith("172.26.")  || ip.startsWith("172.27.")
            || ip.startsWith("172.28.")  || ip.startsWith("172.29.")
            || ip.startsWith("172.30.")  || ip.startsWith("172.31.")
            || ip.startsWith("192.168.")
            || ip.startsWith("169.254."); // link-local
    }

    private boolean isSystemAddress(String ip) {
        return ip.startsWith("127.")
            || ip.equals("::1")
            || ip.startsWith("224.")
            || ip.startsWith("239.")
            || ip.equals("255.255.255.255")
            || ip.equals("0.0.0.0")
            || ip.startsWith("169.254.");
    }

    private boolean shouldAlert(String key, long now) {
        return shouldAlert(key, now, COOLDOWN_MS);
    }

    private boolean shouldAlert(String key, long now, long cooldown) {
        Long last = lastAlertTime.get(key);
        if (last == null || (now - last) > cooldown) {
            lastAlertTime.put(key, now);
            return true;
        }
        return false;
    }

    public void cleanup() {
        long cutoff = System.currentTimeMillis() - (COOLDOWN_MS * 10);
        lastAlertTime.entrySet().removeIf(e -> e.getValue() < cutoff);
    }
    private String normalize(String ip) {
        if (ip == null) return null;
        return ip.trim()
            .replaceAll("^/", "")
            .replaceAll(":.*$", "");
    }
}