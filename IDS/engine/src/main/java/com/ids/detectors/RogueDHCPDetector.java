package com.ids.detectors;

import com.ids.alerts.AlertManager;
import com.ids.models.PacketContext;
import com.ids.models.ThreatEvent;
import com.ids.models.ThreatEvent.Severity;
import com.ids.models.ThreatEvent.ThreatType;
import com.ids.network.NetworkWhitelist;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Detects rogue DHCP servers — any unknown MAC sending DHCP OFFERs or ACKs.
 *
 * Logic:
 * DHCP server → client traffic is UDP src=67 dst=68.
 * If the raw UDP payload is available, we verify DHCP option 53 (message
 * type). If not, we flag any un-trusted MAC on port 67→68 conservatively.
 *
 * FIX — SECURITY BYPASS REMOVED:
 * This detector used to have an "auto-learn" mode: if no trusted MAC was
 * configured, it silently trusted whichever DHCP server sent the FIRST
 * OFFER/ACK after startup. That is a real bypass, not just a tuning issue —
 * classic DHCP-spoofing attacks work by racing the legitimate DHCP server
 * to answer client requests first (win the race, become the client's
 * gateway/DNS, sit in the middle of their traffic). If the engine
 * (re)started at the wrong moment and an attacker's rogue server answered
 * first, THE ATTACKER got permanently trusted and the real server got
 * flagged as rogue — the detector's only defense could be defeated by
 * exactly the attack it exists to catch.
 *
 * There is no implicit trust path anymore. Trusted DHCP server MACs must
 * be configured explicitly via NetworkWhitelist (network.dhcp.trusted.servers
 * in ids-whitelist.properties). If none are configured, this detector
 * alerts on every DHCP server response it sees — including your legitimate
 * one — until configured. That is a deliberately noisy default: noisy-but-
 * safe beats silent-but-exploitable. NetworkWhitelist logs a startup
 * warning when this list is empty specifically so the noise has an obvious
 * explanation instead of looking like a bug.
 */
public class RogueDHCPDetector implements Detector {

    private static final int DHCP_SERVER_PORT = 67;
    private static final int DHCP_CLIENT_PORT = 68;
    private static final long COOLDOWN_MS = 10_000L;

    private final Map<String, Long> lastAlerts = new ConcurrentHashMap<>();

    private final AlertManager alertManager;
    private final NetworkWhitelist whitelist;

    public RogueDHCPDetector(AlertManager alertManager, NetworkWhitelist whitelist) {
        this.alertManager = alertManager;
        this.whitelist = whitelist;
    }

    /**
     * @param ctx parsed packet context
     * @param udpPayload raw UDP payload bytes — pass null if unavailable
     */
    public void analyze(PacketContext ctx, byte[] udpPayload) {

        if (!ctx.isUdp()) return;
        if (ctx.getSrcPort() != DHCP_SERVER_PORT) return;
        if (ctx.getDstPort() != DHCP_CLIENT_PORT) return;

        String srcIP = ctx.getSrcIp();
        String srcMac = ctx.getSrcMac();
        String dstIP = ctx.getDstIp();
        String dstMac = ctx.getDstMac();
        long now = ctx.getTimestamp();

        if (srcMac == null) return;

        // FIX: no more auto-learn. Every DHCP server response from a MAC
        // that isn't explicitly configured as trusted gets flagged — full
        // stop, no "first one wins" exception.
        if (whitelist.isTrustedDhcpServer(srcMac)) return;

        // Unknown MAC on DHCP server port — check message type if payload available
        if (udpPayload != null && !isDhcpServerMessage(udpPayload)) return;

        String srcMacLower = srcMac.toLowerCase();

        Long last = lastAlerts.get(srcMacLower);
        if (last != null && (now - last) < COOLDOWN_MS) return;

        lastAlerts.put(srcMacLower, now);

        alertManager.raise(new ThreatEvent(
            ThreatType.ROGUE_DHCP,
            srcIP, srcMac, dstIP, dstMac,
            1, 0,
            "Rogue DHCP server: " + srcMac + " (" + srcIP + ") — may redirect clients to malicious gateway. "
            + "If this is actually your legitimate DHCP server, add its MAC to "
            + "network.dhcp.trusted.servers in ids-whitelist.properties.",
            Severity.CRITICAL,
            "UDP", "DHCP",
            DHCP_SERVER_PORT
        ));
    }

    /**
     * Parses DHCP option 53 from the raw UDP payload.
     * Returns true if message type is OFFER (2) or ACK (5).
     * Fixed DHCP header = 236 bytes, magic cookie = 4 bytes, then options.
     */
    private boolean isDhcpServerMessage(byte[] p) {
        if (p.length < 244) return false;

        // Magic cookie: 99.130.83.99
        if ((p[236] & 0xFF) != 99 || (p[237] & 0xFF) != 130 ||
            (p[238] & 0xFF) != 83 || (p[239] & 0xFF) != 99) return false;

        int i = 240;
        while (i < p.length) {
            int opt = p[i] & 0xFF;
            if (opt == 255) break; // END
            if (opt == 0) { i++; continue; } // PAD
            if (i + 1 >= p.length) break;
            int len = p[i + 1] & 0xFF;
            if (opt == 53 && len == 1 && i + 2 < p.length) {
                int type = p[i + 2] & 0xFF;
                return type == 2 || type == 5; // OFFER or ACK
            }
            i += 2 + len;
        }
        return true; // couldn't parse — flag conservatively
    }

    public void cleanup() {
        long now = System.currentTimeMillis();
        lastAlerts.entrySet().removeIf(e -> (now - e.getValue()) > COOLDOWN_MS * 6);
    }
}