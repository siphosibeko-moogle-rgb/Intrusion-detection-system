package com.ids.detectors;

import com.ids.alerts.AlertSink;
import com.ids.models.PacketContext;
import com.ids.models.ThreatEvent;
import com.ids.models.ThreatEvent.Severity;
import com.ids.models.ThreatEvent.ThreatType;
import com.ids.network.NetworkWhitelist;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Detects file transfer sessions by protocol signature.
 *
 * Complements DataExfiltrationDetector (which is volume-based / MB thresholds).
 * This detector is protocol-based — it flags the transfer the moment a known
 * file-transfer protocol is seen from an unexpected source.
 *
 * Checks:
 *   FTP active session    — plain-text FTP (port 21) — credentials in the clear
 *   Unauthorised FTP data — FTP data channel (port 20) from an unexpected host
 *   SMB outside subnet    — SMB (445/139) from external or non-whitelisted IP
 *   SCP / SFTP session    — SSH on port 22 carrying large payloads (file content)
 *   Cleartext FTP creds   — USER / PASS commands visible in TCP payload
 *
 * What it does NOT duplicate:
 *   - Volume thresholds (50 MB / 200 MB) — that is DataExfiltrationDetector's job.
 *   - ARP / DNS / ICMP — handled by dedicated detectors.
 *
 * FIX: previously took a raw `String localSubnet` and did
 * `!srcIP.startsWith(localSubnet)` to decide "external" — the exact
 * Docker/K8s-subnet blind spot already fixed in AfterHoursDetector,
 * UserBehaviorAnomalyDetector, DataExfiltrationDetector, and
 * LateralMovementDetector, just missed here. Traffic from a container on
 * Docker's default bridge range (172.17.x–172.30.x) would read as
 * "external" and fire SMB_EXTERNAL incorrectly. Now uses
 * NetworkWhitelist.isInternal(), the single source of truth for that
 * check. Also replaced the separately-passed `List<String> trustedServers`
 * with NetworkWhitelist.isKnownServer() — one server registry
 * (server.N in ids-whitelist.properties) instead of two lists that can
 * drift out of sync with each other.
 */
public class FileTransferDetector implements Detector {

    private static final int  FTP_CTRL_PORT  = 21;
    private static final int  FTP_DATA_PORT  = 20;
    private static final int  SSH_PORT       = 22;
    private static final int  SMB_PORT       = 445;
    private static final int  NETBIOS_PORT   = 139;

    // SCP/SFTP heuristic: SSH payload > this size suggests file content, not just commands
    private static final int  SCP_PAYLOAD_THRESHOLD = 1024;  // bytes per segment

    private static final long COOLDOWN_MS = 15_000L;

    private final Map<String, Long> lastAlerts = new ConcurrentHashMap<>();

    private final AlertSink alertManager;
    private final NetworkWhitelist whitelist;

    public FileTransferDetector(AlertSink alertManager, NetworkWhitelist whitelist) {
        this.alertManager = alertManager;
        this.whitelist = whitelist;
    }

    public void analyze(PacketContext ctx, String tcpPayload) {

        if (!ctx.isTcp()) return;

        String srcIP  = ctx.getSrcIp();
        String dstIP  = ctx.getDstIp();
        String srcMac = ctx.getSrcMac();
        String dstMac = ctx.getDstMac();
        int    dstPort = ctx.getDstPort();
        int    srcPort = ctx.getSrcPort();
        long   now    = ctx.getTimestamp();

        if (srcIP == null || dstIP == null) return;

        //FTP CONTROL SESSION
        // Plain-text FTP is inherently risky; alert whenever it's used
        if (dstPort == FTP_CTRL_PORT) {
            if (!whitelist.isKnownServer(dstIP)) {
                raise("FTP_CTRL:" + srcIP + "->" + dstIP, ThreatType.FTP_SESSION,
                        srcIP, srcMac, dstIP, dstMac, now,
                        "FTP session to non-whitelisted server: " + srcIP + " → " + dstIP + ":21 (credentials sent in cleartext)",
                        Severity.LOW, FTP_CTRL_PORT);
            }
        }

        //2. FTP DATA CHANNEL
        if (dstPort == FTP_DATA_PORT || srcPort == FTP_DATA_PORT) {
            if (!whitelist.isKnownServer(srcIP) && !whitelist.isKnownServer(dstIP)) {
                raise("FTP_DATA:" + srcIP + "->" + dstIP, ThreatType.FTP_DATA_TRANSFER,
                        srcIP, srcMac, dstIP, dstMac, now,
                        "FTP data channel between non-whitelisted hosts: " + srcIP + " ↔ " + dstIP,
                        Severity.HIGH, FTP_DATA_PORT);
            }
        }

        //SMB FROM OUTSIDE SUBNET
        if (dstPort == SMB_PORT || dstPort == NETBIOS_PORT) {
            // FIX: was `!srcIP.startsWith(localSubnet)` — see class doc above.
            boolean srcExternal = !whitelist.isInternal(srcIP);
            if (srcExternal) {
                raise("SMB_EXT:" + srcIP, ThreatType.SMB_EXTERNAL,
                        srcIP, srcMac, dstIP, dstMac, now,
                        "SMB connection from external host: " + srcIP + " → " + dstIP + ":" + dstPort,
                        Severity.CRITICAL, dstPort);
            }
        }

        // SCP / SFTP HEURISTIC
        // SSH carrying large payloads (> SCP_PAYLOAD_THRESHOLD per segment) = file transfer
        if ((dstPort == SSH_PORT || srcPort == SSH_PORT) && tcpPayload != null) {
            if (tcpPayload.length() >= SCP_PAYLOAD_THRESHOLD) {
                String direction = dstPort == SSH_PORT ? srcIP + " → " + dstIP : dstIP + " → " + srcIP;
                raise("SCP:" + srcIP + "->" + dstIP, ThreatType.SCP_SFTP_TRANSFER,
                        srcIP, srcMac, dstIP, dstMac, now,
                        "SCP/SFTP file transfer detected: " + direction + " (" + tcpPayload.length() + " bytes/seg)",
                        Severity.INFO, SSH_PORT);
            }
        }

        //CLEARTEXT FTP CREDENTIALS
        if (tcpPayload != null) {
            String upper = tcpPayload.toUpperCase();
            if (upper.startsWith("USER ") || upper.startsWith("PASS ")) {
                raise("FTP_CRED:" + srcIP, ThreatType.FTP_CLEARTEXT_CREDENTIALS,
                        srcIP, srcMac, dstIP, dstMac, now,
                        "Cleartext FTP credentials from " + srcIP + " → " + dstIP,
                        Severity.HIGH, FTP_CTRL_PORT);
            }
        }
    }

    private void raise(String key, ThreatType type,
                        String srcIP, String srcMac,
                        String dstIP, String dstMac,
                        long now, String details, Severity sev, int port) {
        Long last = lastAlerts.get(key);
        if (last != null && (now - last) < COOLDOWN_MS) return;
        lastAlerts.put(key, now);
        alertManager.raise(new ThreatEvent(
                type, srcIP, srcMac, dstIP, dstMac,
                1, 0, details, sev, "TCP", "FILE_TRANSFER", port
        ));
    }

    public void cleanup() {
        long now = System.currentTimeMillis();
        lastAlerts.entrySet().removeIf(e -> (now - e.getValue()) > COOLDOWN_MS * 4);
    }
}