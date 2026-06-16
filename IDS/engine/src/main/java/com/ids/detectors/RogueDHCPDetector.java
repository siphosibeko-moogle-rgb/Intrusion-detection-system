package com.ids.detectors;

import com.ids.alerts.AlertManager;
import com.ids.models.PacketContext;
import com.ids.models.ThreatEvent;
import com.ids.models.ThreatEvent.Severity;
import com.ids.models.ThreatEvent.ThreatType;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Detects rogue DHCP servers — any unknown MAC sending DHCP OFFERs or ACKs.
 *
 * Logic:
 *   DHCP server → client traffic is UDP src=67 dst=68.
 *   The legitimate server MAC is known at startup.
 *   Any DHCP OFFER (type 2) or ACK (type 5) from a different MAC is a rogue
 *   server that can redirect all client traffic through an attacker gateway.
 *
 *   If the raw UDP payload is available, we verify DHCP option 53 (message
 *   type). If not, we flag any unknown MAC on port 67→68 conservatively.
 */
public class RogueDHCPDetector implements Detector {

    private static final int  DHCP_SERVER_PORT = 67;
    private static final int  DHCP_CLIENT_PORT = 68;
    private static final long COOLDOWN_MS      = 10_000L;

    private final Set<String>       trustedMacs = ConcurrentHashMap.newKeySet();
    private final Map<String, Long> lastAlerts  = new ConcurrentHashMap<>();

    private final AlertManager alertManager;

    /**
     * @param trustedServerMac MAC of the legitimate DHCP server (case-insensitive).
     *                         Pass null to auto-learn the first server seen.
     */
    public RogueDHCPDetector(AlertManager alertManager, String trustedServerMac) {
        this.alertManager = alertManager;
        if (trustedServerMac != null && !trustedServerMac.isBlank()) {
            trustedMacs.add(trustedServerMac.toLowerCase());
        }
    }

    /** Add extra trusted MACs (e.g. redundant DHCP servers). */
    public void addTrustedMac(String mac) {
        if (mac != null) trustedMacs.add(mac.toLowerCase());
    }

    /**
     * @param ctx        parsed packet context
     * @param udpPayload raw UDP payload bytes — pass null if unavailable
     */
    public void analyze(PacketContext ctx, byte[] udpPayload) {

        if (!ctx.isUdp()) return;
        if (ctx.getSrcPort() != DHCP_SERVER_PORT) return;
        if (ctx.getDstPort() != DHCP_CLIENT_PORT) return;

        String srcIP  = ctx.getSrcIp();
        String srcMac = ctx.getSrcMac();
        String dstIP  = ctx.getDstIp();
        String dstMac = ctx.getDstMac();
        long   now    = ctx.getTimestamp();

        if (srcMac == null) return;

        String srcMacLower = srcMac.toLowerCase();

        // Auto-learn mode: trust the first DHCP server we see
        if (trustedMacs.isEmpty()) {
            trustedMacs.add(srcMacLower);
            return;
        }

        if (trustedMacs.contains(srcMacLower)) return;

        // Unknown MAC on DHCP server port — check message type if payload available
        if (udpPayload != null && !isDhcpServerMessage(udpPayload)) return;

        Long last = lastAlerts.get(srcMacLower);
        if (last != null && (now - last) < COOLDOWN_MS) return;

        lastAlerts.put(srcMacLower, now);

        alertManager.raise(new ThreatEvent(
                ThreatType.ROGUE_DHCP,
                srcIP, srcMac, dstIP, dstMac,
                1, 0,
                "Rogue DHCP server: " + srcMac + " (" + srcIP + ") — may redirect clients to malicious gateway",
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
            if (opt == 255) break;             // END
            if (opt == 0)  { i++; continue; }  // PAD
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