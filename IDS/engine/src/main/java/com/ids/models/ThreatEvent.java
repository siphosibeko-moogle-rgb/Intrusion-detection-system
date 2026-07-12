package com.ids.models;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

public class ThreatEvent {

    public enum Severity {
        // INFO: event is worth recording for context/correlation but carries
        // no risk on its own (e.g. an SFTP transfer happened). Ordinal order
        // matters — the floor clamp in the constructor compares ordinals.
        INFO, LOW, MEDIUM, HIGH, CRITICAL
    }

    /**
     * Every ThreatType carries a defaultSeverity — the floor below which an
     * alert of that type can never be raised, regardless of what a detector
     * passes in. This is the Snort/Suricata "classtype default priority"
     * pattern: detectors keep their existing dynamic escalation logic
     * (brute-force attempt count, DNS entropy, SYN-flood source spread,
     * after-hours + sensitive-port combinations, etc.) completely
     * untouched — that logic is genuinely useful signal and stays. The
     * floor only protects against a detector accidentally under-reporting
     * severity for a type that's inherently at least this dangerous, and
     * gives one place to see and audit the baseline across all 47 threat
     * types instead of it being scattered across 20 detector files.
     *
     * IMPORTANT: a floor can only RAISE severity, never lower it. If a
     * detector is currently hardcoding something above the floor you want
     * (e.g. it always alerts HIGH but you want the type's baseline at
     * MEDIUM), that detector's call site needs its own edit — the floor
     * alone won't pull it down. See engine changelog for the specific
     * detector-side fixes that accompanied this: NMAP_PORT_SWEEP
     * (CRITICAL→HIGH), HTTP_SCANNER_AGENT / HTTP_OVERSIZED_URI
     * (HIGH→MEDIUM), UNKNOWN_IP / UNKNOWN_MAC (MEDIUM→LOW), ARP_FLOOD
     * (HIGH→MEDIUM).
     */
    public enum ThreatType {
        // Recon / scanning — nobody's compromised anything yet
        ICMP_FLOOD(Severity.HIGH),
        ICMP_PING_SWEEP(Severity.MEDIUM),
        // Severity philosophy for recon types: a port scan is unauthenticated
        // reconnaissance — real signal, but nobody has touched anything yet.
        // Baseline is MEDIUM across the scan family. Detectors still escalate
        // above the floor where the *behavior* justifies it: NULL/FIN/XMAS
        // call sites pass HIGH because those flag combinations never occur in
        // legitimate traffic (they are hand-crafted evasion packets), and the
        // port-sweep call site passes HIGH because 20+ ports on one host in
        // 2s is unambiguous active probing.
        NMAP_SYN_SCAN(Severity.MEDIUM),
        NMAP_NULL_SCAN(Severity.MEDIUM),
        NMAP_FIN_SCAN(Severity.MEDIUM),
        NMAP_XMAS_SCAN(Severity.MEDIUM),
        NMAP_UDP_SCAN(Severity.MEDIUM),
        NMAP_PORT_SWEEP(Severity.MEDIUM),
        // Not currently raised by any detector — reserved for a future
        // OS-fingerprinting signal. HIGH: OS fingerprinting means the
        // attacker has moved past discovery into targeting specific hosts.
        NMAP_OS_DETECTION(Severity.HIGH),
        LOW_AND_SLOW_SCAN(Severity.HIGH),
        PORT_KNOCKING(Severity.HIGH),

        // Identity / device tracking
        // FIX: was MEDIUM — a genuinely new device on the LAN is common
        // (guest laptops, new phones joining wifi) and shouldn't sit at the
        // same tier as e.g. a DNS flood. Matches the severity
        // WhitelistViolationDetector.analyzeArp() already used for the
        // equivalent "new device via ARP" case (Severity.LOW).
        UNKNOWN_IP(Severity.LOW),
        UNKNOWN_MAC(Severity.LOW),
        OUTSIDE_SUBNET(Severity.HIGH),
        ROGUE_DHCP(Severity.CRITICAL),

        // ARP / MITM
        ARP_SPOOFING(Severity.HIGH),
        ARP_POISONING(Severity.CRITICAL),
        // FIX: was HIGH — a flood of ARP replies alone (no MAC/IP conflict,
        // no gateway impersonation) is noisy but not yet evidence of an
        // active MITM; ARP_SPOOFING and ARP_POISONING cover the confirmed
        // cases and stay HIGH/CRITICAL.
        ARP_FLOOD(Severity.MEDIUM),
        // FIX: was MEDIUM — a non-gateway unsolicited ARP reply happens on
        // every DHCP renewal, Wi-Fi reconnect, and VRRP failover. The call
        // site in ArpSpoofingDetector still escalates to CRITICAL when the
        // sender claims to be the gateway (actual MITM setup).
        GRATUITOUS_ARP(Severity.LOW),

        // DNS
        DNS_TUNNELING(Severity.MEDIUM),
        DNS_FLOOD(Severity.HIGH),
        DNS_AMPLIFICATION(Severity.MEDIUM),

        // Exfiltration / lateral movement — highest-confidence categories
        BULK_DOWNLOAD(Severity.HIGH),
        DATA_EXFILTRATION(Severity.HIGH),
        SUSTAINED_LARGE_TRANSFER(Severity.HIGH),
        DATA_STAGING(Severity.HIGH),
        DATA_STAGING_MULTI_PORT(Severity.HIGH),
        BEACONING(Severity.HIGH),
        LATERAL_MOVEMENT(Severity.CRITICAL),

        // Time-based access
        // FIX (per your call): floor lowered to LOW for all three. This is
        // a pure floor change — AfterHoursDetector's own escalation logic
        // (MEDIUM baseline → HIGH for late-night-or-sensitive → CRITICAL
        // for late-night-AND-sensitive) is untouched and still fires
        // exactly as before, since MEDIUM/HIGH/CRITICAL all sit above a
        // LOW floor. AFTER_HOURS_SERVER_ACCESS is currently a flat HIGH at
        // its one call site in AfterHoursDetector — that stays HIGH in
        // practice too, since the floor only sets a minimum. Flagging this
        // explicitly since "sensitive port after hours" is arguably worth
        // more than a LOW floor implies; let me know if you want the
        // AFTER_HOURS_SERVER_ACCESS call site itself pulled down to a flat
        // LOW rather than just floored there.
        AFTER_HOURS_ACCESS(Severity.LOW),
        WEEKEND_ACCESS(Severity.LOW),
        AFTER_HOURS_SERVER_ACCESS(Severity.LOW),

        // Auth
        BRUTE_FORCE_ATTEMPT(Severity.MEDIUM),
        // Not currently raised — packet capture alone can't see
        // application-layer auth success on encrypted protocols (SSH/RDP).
        // Reserved for when/if a success signal (e.g. correlated with a
        // subsequent large data pull) gets added.
        BRUTE_FORCE_SUCCESS(Severity.HIGH),

        // HTTP / web
        HTTP_FLOOD(Severity.HIGH),
        // FIX: was HIGH — a single oversized URI on its own could be a
        // legitimate signed URL (S3, JWT-bearing redirect) rather than a
        // path-traversal/overflow attempt. Dropped to MEDIUM; still worth
        // an analyst's attention, not worth the same tier as a confirmed
        // flood or injection payload.
        HTTP_OVERSIZED_URI(Severity.MEDIUM),
        HTTP_SUSPICIOUS_VERB(Severity.MEDIUM),
        // FIX: was HIGH — a scanner User-Agent string alone (someone's
        // client claims to be "sqlmap") is weaker evidence than an actual
        // injection-shaped payload, which SQL_INJECTION's own rules already
        // rate HIGH/CRITICAL depending on the specific pattern matched.
        // Dropped to MEDIUM so UA-string detection doesn't outrank
        // confirmed payload matches.
        HTTP_SCANNER_AGENT(Severity.MEDIUM),
        // Lowest rung actually used across SqlInjectionDetector's rules
        // (TAUTOLOGY, COMMENT_TRUNCATION, SCHEMA_ENUMERATION = HIGH;
        // UNION_SELECT, STACKED_QUERY, TIME_BASED_BLIND, DB_COMMAND_EXEC =
        // CRITICAL). That per-rule severity is already well-modeled and is
        // left as-is; this floor just documents the baseline.
        SQL_INJECTION(Severity.HIGH),

        // File transfer
        // FIX: was MEDIUM — the *session existing* is a policy observation
        // (cleartext protocol in use), not an active attack. The cleartext
        // credential capture itself is what carries real risk and that type
        // stays HIGH below.
        FTP_SESSION(Severity.LOW),
        FTP_DATA_TRANSFER(Severity.HIGH),
        FTP_CLEARTEXT_CREDENTIALS(Severity.HIGH),
        SMB_EXTERNAL(Severity.CRITICAL),
        // FIX: was MEDIUM — an SCP/SFTP transfer over SSH is routine admin
        // activity, recorded for correlation (e.g. staged data leaving via
        // SSH after a DATA_STAGING alert), not a threat by itself.
        // DataExfiltrationDetector owns the volume-based escalation.
        SCP_SFTP_TRANSFER(Severity.INFO),

        // User behavior anomaly (UBA)
        UBA_NEW_PROTOCOL(Severity.MEDIUM),
        UBA_NEW_DESTINATION(Severity.MEDIUM),
        UBA_NEW_SERVICE_PORT(Severity.MEDIUM),
        UBA_BURST_ACTIVITY(Severity.HIGH),

        // DoS / DDoS
        SYN_FLOOD(Severity.HIGH);

        private final Severity defaultSeverity;

        ThreatType(Severity defaultSeverity) {
            this.defaultSeverity = defaultSeverity;
        }

        public Severity getDefaultSeverity() {
            return defaultSeverity;
        }
    }

    private final ThreatType type;

    @JsonProperty("sourceIp")
    private final String sourceIP;

    @JsonProperty("sourceMac")
    private final String sourceMac;

    @JsonProperty("destinationIp")
    private final String destinationIP;

    @JsonProperty("destinationMac")
    private final String destinationMac;

    private final int packetCount;
    private final long windowMillis;

    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private final LocalDateTime timestamp;

    private final String details;
    private final Severity severity;
    private final String protocol;
    private final String requestType;
    private final int destinationPort;

    private String hostName = "ids-sensor";

    // ── Confidence / provenance metadata ────────────────────────────────
    // How certain the engine is that this event is genuinely malicious,
    // 0–100. Defaults to 60 ("a single threshold-based rule matched");
    // detectors override via withConfidence() when they have behavioral
    // corroboration (e.g. zero completed handshakes behind a SYN burst)
    // or when the evidence is circumstantial. Flows through toMap() to the
    // backend so analysts can sort/triage by confidence and so future
    // ML/false-positive feedback loops have a target variable to learn on.
    private int    confidenceScore  = 60;
    private String confidenceReason = "Threshold-based rule match";
    private String detectedBy       = "ids-engine";
    private String ruleVersion      = "1.0";
    private String mitreAttack; // set from MITRE_MAP in ctor; overridable

    // MITRE ATT&CK technique per threat type. Types with no clean mapping
    // (UBA anomalies, unknown-device events) are deliberately absent —
    // a wrong mapping is worse than none.
    private static final Map<ThreatType, String> MITRE_MAP = new HashMap<>();
    static {
        // Recon / scanning
        MITRE_MAP.put(ThreatType.NMAP_SYN_SCAN,     "T1046");     // Network Service Discovery
        MITRE_MAP.put(ThreatType.NMAP_NULL_SCAN,    "T1046");
        MITRE_MAP.put(ThreatType.NMAP_FIN_SCAN,     "T1046");
        MITRE_MAP.put(ThreatType.NMAP_XMAS_SCAN,    "T1046");
        MITRE_MAP.put(ThreatType.NMAP_UDP_SCAN,     "T1046");
        MITRE_MAP.put(ThreatType.NMAP_PORT_SWEEP,   "T1046");
        MITRE_MAP.put(ThreatType.NMAP_OS_DETECTION, "T1046");
        MITRE_MAP.put(ThreatType.LOW_AND_SLOW_SCAN, "T1046");
        MITRE_MAP.put(ThreatType.ICMP_PING_SWEEP,   "T1018");     // Remote System Discovery
        MITRE_MAP.put(ThreatType.PORT_KNOCKING,     "T1205.001"); // Traffic Signaling: Port Knocking
        // MITM / spoofing
        MITRE_MAP.put(ThreatType.ARP_SPOOFING,      "T1557.002"); // ARP Cache Poisoning
        MITRE_MAP.put(ThreatType.ARP_POISONING,     "T1557.002");
        MITRE_MAP.put(ThreatType.GRATUITOUS_ARP,    "T1557.002");
        MITRE_MAP.put(ThreatType.ROGUE_DHCP,        "T1557.003"); // DHCP Spoofing
        // C2 / exfiltration
        MITRE_MAP.put(ThreatType.DNS_TUNNELING,             "T1071.004"); // App Protocol: DNS
        MITRE_MAP.put(ThreatType.BEACONING,                 "T1071");
        MITRE_MAP.put(ThreatType.DATA_EXFILTRATION,         "T1048");
        MITRE_MAP.put(ThreatType.BULK_DOWNLOAD,             "T1048");
        MITRE_MAP.put(ThreatType.SUSTAINED_LARGE_TRANSFER,  "T1048");
        MITRE_MAP.put(ThreatType.DATA_STAGING,              "T1074");
        MITRE_MAP.put(ThreatType.DATA_STAGING_MULTI_PORT,   "T1074");
        MITRE_MAP.put(ThreatType.FTP_DATA_TRANSFER,         "T1048.003");
        MITRE_MAP.put(ThreatType.FTP_CLEARTEXT_CREDENTIALS, "T1040");     // Network Sniffing exposure
        MITRE_MAP.put(ThreatType.SCP_SFTP_TRANSFER,         "T1048.002");
        // Lateral movement / access
        MITRE_MAP.put(ThreatType.LATERAL_MOVEMENT,     "T1021");
        MITRE_MAP.put(ThreatType.SMB_EXTERNAL,         "T1021.002");
        MITRE_MAP.put(ThreatType.BRUTE_FORCE_ATTEMPT,  "T1110");
        MITRE_MAP.put(ThreatType.BRUTE_FORCE_SUCCESS,  "T1110");
        // Web
        MITRE_MAP.put(ThreatType.SQL_INJECTION,      "T1190");     // Exploit Public-Facing App
        MITRE_MAP.put(ThreatType.HTTP_SCANNER_AGENT, "T1595.002"); // Active Scanning: Vuln Scanning
        // DoS
        MITRE_MAP.put(ThreatType.SYN_FLOOD,         "T1498");
        MITRE_MAP.put(ThreatType.ICMP_FLOOD,        "T1498");
        MITRE_MAP.put(ThreatType.DNS_FLOOD,         "T1498");
        MITRE_MAP.put(ThreatType.DNS_AMPLIFICATION, "T1498.002");
        MITRE_MAP.put(ThreatType.HTTP_FLOOD,        "T1498");
    }

    public ThreatEvent(
        ThreatType type,
        String sourceIP,
        String sourceMac,
        String destinationIP,
        String destinationMac,
        int packetCount,
        long windowMillis,
        String details,
        Severity severity,
        String protocol,
        String requestType,
        int destinationPort
    ) {
        this.type = type;
        this.sourceIP = sourceIP;
        this.sourceMac = sourceMac;
        this.destinationIP = destinationIP;
        this.destinationMac = destinationMac;
        this.packetCount = packetCount;
        this.windowMillis = windowMillis;
        this.timestamp = LocalDateTime.now();
        this.details = details;
        // FIX: clamp to the type's floor. A detector can always escalate
        // above the floor (that's how brute-force count, DNS entropy, and
        // SYN-flood spread escalation all keep working unchanged) but can
        // never under-report below it, even by mistake in a future edit.
        Severity floor = type.getDefaultSeverity();
        this.severity = (severity == null || severity.ordinal() < floor.ordinal())
            ? floor
            : severity;
        this.protocol = protocol;
        this.requestType = requestType;
        this.destinationPort = destinationPort;
        this.mitreAttack = MITRE_MAP.get(type);
    }

    // ── Fluent metadata setters ─────────────────────────────────────────
    // Optional — every existing `new ThreatEvent(...)` call site keeps
    // working unchanged with sensible defaults. Detectors chain these when
    // they can say something better than the default:
    //   alertManager.raise(new ThreatEvent(...)
    //       .withConfidence(90, "15 half-open SYNs, 0 completed handshakes")
    //       .withDetection("NmapScanDetector", "2.0"));

    public ThreatEvent withConfidence(int score, String reason) {
        this.confidenceScore = Math.max(0, Math.min(100, score));
        if (reason != null && !reason.isBlank()) this.confidenceReason = reason;
        return this;
    }

    public ThreatEvent withDetection(String detector, String ruleVersion) {
        if (detector != null)    this.detectedBy  = detector;
        if (ruleVersion != null) this.ruleVersion = ruleVersion;
        return this;
    }

    public ThreatEvent withMitre(String techniqueId) {
        this.mitreAttack = techniqueId;
        return this;
    }

    //Convert to API-compatible structure
    public Map<String, Object> toMap() {
        Map<String, Object> map = new HashMap<>();

        map.put("threatType", type.name());
        map.put("severity", severity.name());
        map.put("sourceIp", sourceIP);
        map.put("sourceMac", sourceMac != null ? sourceMac : ""); // ← TOP LEVEL
        map.put("destIp", destinationIP != null ? destinationIP : ""); // ← "destIp" not "destinationIp"
        map.put("destMac", destinationMac != null ? destinationMac : "");
        map.put("protocol", protocol);
        map.put("requestType", requestType);
        map.put("packetCount", packetCount);
        map.put("windowMs", windowMillis);
        // FIX: was timestamp.toString() — a zoneless LocalDateTime string.
        // The backend appends "Z" and parses it as UTC, so on any sensor not
        // running in UTC every alert was stored offset by the sensor's UTC
        // offset (+2h in Africa/Johannesburg), skewing timelines and
        // since-queries. Convert through the system zone to a real Instant;
        // its ISO string already ends in "Z" so ingest passes it through.
        map.put("timestamp",
            timestamp.atZone(java.time.ZoneId.systemDefault()).toInstant().toString());
        map.put("details", details != null ? details : "");
        map.put("destinationPort", destinationPort);
        map.put("confidenceScore", confidenceScore);
        map.put("confidenceReason", confidenceReason != null ? confidenceReason : "");
        map.put("detectedBy", detectedBy != null ? detectedBy : "");
        map.put("ruleVersion", ruleVersion != null ? ruleVersion : "");
        map.put("mitreAttack", mitreAttack != null ? mitreAttack : "");

        return map;
    }

    // getters (unchanged)
    public ThreatType getType(){ return type; }
    public String getSourceIP(){ return sourceIP; }
    public String getSourceMac(){ return sourceMac; }
    public String getDestinationIP(){ return destinationIP; }
    public String getDestinationMac(){ return destinationMac; }
    public int getPacketCount(){ return packetCount; }
    public long getWindowMillis(){ return windowMillis; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public String getDetails() { return details; }
    public Severity getSeverity(){ return severity; }
    public String getProtocol(){ return protocol; }
    public String getRequestType(){ return requestType; }
    public int getDestinationPort(){ return destinationPort; }
    public String getHostName(){ return hostName; }
    public void setHostName(String h){ this.hostName = h; }
    public int getConfidenceScore(){ return confidenceScore; }
    public String getConfidenceReason(){ return confidenceReason; }
    public String getDetectedBy(){ return detectedBy; }
    public String getRuleVersion(){ return ruleVersion; }
    public String getMitreAttack(){ return mitreAttack; }

    @Override
    public String toString() {
        return String.format("[%s] %s | src=%s (%s) -> dst=%s | severity=%s | %s",
            timestamp, type.name(), sourceIP, sourceMac, destinationIP, severity, details);
    }
}