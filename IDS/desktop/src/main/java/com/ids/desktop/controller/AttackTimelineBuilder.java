package com.ids.desktop.controller;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Translates a chronological list of alerts (for one IP) into a
 * human-readable attack timeline narrative.
 *
 * Logic: We classify each alert into a "kill chain phase", then collapse
 * consecutive alerts of the same phase into a single timeline event.
 * This prevents 200 port-scan alerts from becoming 200 timeline entries.
 *
 * Why classify by phase rather than threat type?
 * Because the same attacker may switch tools but stay in the same phase.
 * NMAP_SYN_SCAN and UDP_SCAN both = RECONNAISSANCE. Grouping them gives
 * the analyst a cleaner story: "Recon lasted 4 minutes, then pivoted."
 */
public class AttackTimelineBuilder {

    private static final DateTimeFormatter FMT =
        DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    public enum Phase {
        RECONNAISSANCE("Reconnaissance"),
        SCANNING      ("Scanning"),
        EXPLOITATION  ("⚔Exploitation"),
        C2            ("Command & Control"),
        EXFILTRATION  ("Data Exfiltration"),
        UNKNOWN       ("Unknown Activity");

        public final String label;
        Phase(String label) { this.label = label; }
    }

    public record TimelineEvent(
        Instant  timestamp,
        String   time,       // formatted HH:mm:ss
        Phase    phase,
        String   title,
        String   description,
        String   severity,
        int      alertCount  // how many raw alerts collapsed into this event
    ) {}

    public static List<TimelineEvent> build(JsonNode alertArray) {
        if (alertArray == null || !alertArray.isArray() || alertArray.isEmpty())
            return Collections.emptyList();

        List<TimelineEvent> events = new ArrayList<>();
        Phase   currentPhase = null;
        Instant phaseStart   = null;
        String  phaseSeverity = "LOW";
        int     phaseCount   = 0;
        List<String> phaseThreats = new ArrayList<>();

        for (JsonNode node : alertArray) {
            String  threatType = node.path("threatType").asText("UNKNOWN");
            String  severity   = node.path("severity").asText("LOW");
            Instant ts         = Instant.parse(node.path("timestamp").asText());
            Phase   phase      = classify(threatType);

            if (currentPhase == null) {
                
                currentPhase  = phase;
                phaseStart    = ts;
                phaseSeverity = severity;
                phaseCount    = 1;
                phaseThreats.add(threatType);

            } else if (phase == currentPhase) {
               
                phaseCount++;
                phaseThreats.add(threatType);
                if (severityRank(severity) > severityRank(phaseSeverity))
                    phaseSeverity = severity; 

            } else {
               
                events.add(buildEvent(currentPhase, phaseStart, phaseSeverity,
                                      phaseCount, phaseThreats));
                currentPhase  = phase;
                phaseStart    = ts;
                phaseSeverity = severity;
                phaseCount    = 1;
                phaseThreats  = new ArrayList<>();
                phaseThreats.add(threatType);
            }
        }

        
        if (currentPhase != null)
            events.add(buildEvent(currentPhase, phaseStart, phaseSeverity,
                                  phaseCount, phaseThreats));

        return events;
    }

    private static TimelineEvent buildEvent(Phase phase, Instant ts,
                                            String severity, int count,
                                            List<String> threats) {
        String title = phaseTitle(phase, threats);
        String desc  = phaseDescription(phase, count, threats);
        return new TimelineEvent(ts, FMT.format(ts), phase, title, desc, severity, count);
    }

   
    public static Phase classify(String threatType) {
        if (threatType == null) return Phase.UNKNOWN;
        return switch (threatType.toUpperCase()) {
            case "UDP_SCAN", "SYN_SCAN", "PORT_SCAN", "NMAP_SCAN",
                 "NMAP_SYN_SCAN", "PING_SWEEP", "HOST_DISCOVERY",
                 "NMAP_NULL_SCAN", "NMAP_FIN_SCAN", "NMAP_XMAS_SCAN"
                 -> Phase.RECONNAISSANCE;

            case "SERVICE_SCAN", "VERSION_SCAN", "OS_DETECTION",
                 "BANNER_GRAB"
                 -> Phase.SCANNING;

            case "BRUTE_FORCE", "SSH_BRUTE", "HTTP_BRUTE",
                 "CREDENTIAL_STUFFING", "FTP_BRUTE", "RDP_BRUTE",
                 "SQL_INJECTION", "XSS", "COMMAND_INJECTION",
                 "PATH_TRAVERSAL", "LFI", "RFI"
                 -> Phase.EXPLOITATION;

            case "BEACON", "DNS_TUNNEL", "C2_COMMUNICATION",
                 "PERIODIC_BEACON", "ICMP_TUNNEL"
                 -> Phase.C2;

            case "DATA_EXFIL", "LARGE_TRANSFER", "DNS_EXFILTRATION",
                 "HTTP_EXFIL", "UNUSUAL_OUTBOUND"
                 -> Phase.EXFILTRATION;

            default -> Phase.UNKNOWN;
        };
    }

    private static String phaseTitle(Phase phase, List<String> threats) {
    
        String primaryThreat = threats.stream()
            .collect(java.util.stream.Collectors.groupingBy(t -> t,
                     java.util.stream.Collectors.counting()))
            .entrySet().stream()
            .max(Map.Entry.comparingByValue())
            .map(Map.Entry::getKey)
            .orElse("Activity");

        return switch (phase) {
            case RECONNAISSANCE -> "Reconnaissance — " + friendlyName(primaryThreat);
            case SCANNING       -> "Service Scanning — " + friendlyName(primaryThreat);
            case EXPLOITATION   -> "Attack — " + friendlyName(primaryThreat);
            case C2             -> "C2 Communication — " + friendlyName(primaryThreat);
            case EXFILTRATION   -> "Data Exfiltration — " + friendlyName(primaryThreat);
            case UNKNOWN        -> friendlyName(primaryThreat);
        };
    }

    private static String phaseDescription(Phase phase, int count, List<String> threats) {
        long distinct = threats.stream().distinct().count();
        return switch (phase) {
            case RECONNAISSANCE ->
                count + " probe packet" + (count > 1 ? "s" : "") +
                " detected across " + distinct + " technique" + (distinct > 1 ? "s" : "") +
                ". Attacker is mapping the network.";
            case SCANNING ->
                count + " service scan event" + (count > 1 ? "s" : "") +
                " detected. Attacker is identifying running services.";
            case EXPLOITATION ->
                count + " attack attempt" + (count > 1 ? "s" : "") +
                " detected. Attacker is attempting to gain access.";
            case C2 ->
                count + " command & control signal" + (count > 1 ? "s" : "") +
                ". Possible compromised host or persistent connection.";
            case EXFILTRATION ->
                count + " suspicious transfer" + (count > 1 ? "s" : "") +
                " detected. Data may be leaving the network.";
            case UNKNOWN ->
                count + " event" + (count > 1 ? "s" : "") + " with unclassified behavior.";
        };
    }

    private static String friendlyName(String threatType) {
        return switch (threatType.toUpperCase()) {
            case "UDP_SCAN"       -> "UDP Scan";
            case "SYN_SCAN",
                 "NMAP_SYN_SCAN"  -> "SYN Scan";
            case "PORT_SCAN"      -> "Port Scan";
            case "NMAP_SCAN"      -> "Nmap Scan";
            case "PING_SWEEP"     -> "Ping Sweep";
            case "BRUTE_FORCE"    -> "Brute Force";
            case "SSH_BRUTE"      -> "SSH Brute Force";
            case "HTTP_BRUTE"     -> "HTTP Brute Force";
            case "SQL_INJECTION"  -> "SQL Injection";
            case "BEACON"         -> "Beaconing";
            case "DNS_TUNNEL"     -> "DNS Tunneling";
            case "DATA_EXFIL"     -> "Data Exfiltration";
            case "LARGE_TRANSFER" -> "Large Data Transfer";
            default -> threatType.replace("_", " ");
        };
    }

    private static int severityRank(String s) {
        return switch (s == null ? "" : s) {
            case "LOW"      -> 1;
            case "MEDIUM"   -> 2;
            case "HIGH"     -> 3;
            case "CRITICAL" -> 4;
            default         -> 0;
        };
    }
}