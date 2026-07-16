package com.ids.controller;

import com.ids.entity.OrgWhitelistEntry;
import com.ids.model.Alert;
import com.ids.service.AlertService;
import com.ids.service.EngineKeyService;
import com.ids.service.OrgWhitelistService;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.web.bind.annotation.*;
import com.ids.repository.AlertRepository;
import com.ids.repository.AlertSummaryRepository;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Map;
import java.util.List;
import com.ids.dto.IpProfileDTO;

@RestController
@RequestMapping("/api/alerts")
public class AlertController {

    private final AlertService            alertService;
    private final AlertRepository         alertRepository;
    private final AlertSummaryRepository  summaryRepository;
    private final SimpMessagingTemplate   ws;
    private final OrgWhitelistService     orgWhitelistService;
    private final EngineKeyService        engineKeyService;

    public AlertController(AlertService alertService,
                           AlertRepository alertRepository,
                           AlertSummaryRepository summaryRepository,
                           SimpMessagingTemplate ws,
                           OrgWhitelistService orgWhitelistService,
                           EngineKeyService engineKeyService) {
        this.alertService        = alertService;
        this.alertRepository     = alertRepository;
        this.summaryRepository   = summaryRepository;
        this.ws                  = ws;
        this.orgWhitelistService = orgWhitelistService;
        this.engineKeyService    = engineKeyService;
    }

    /**
     * Engine posts alerts here — validated by X-Engine-Key header.
     * No JWT required — the key is hashed and looked up in engine_keys;
     * only status=ACTIVE passes. Never log the raw key.
     */
    @PostMapping("/ingest")
    public ResponseEntity<?> ingest(@RequestHeader(value = "X-Engine-Key", required = false) String key,
                                    @RequestBody Map<String, Object> body) {
        com.ids.model.EngineKey engineKey = engineKeyService.authenticate(key).orElse(null);
        if (engineKey == null)
            return ResponseEntity.status(401).body(Map.of("error", "Invalid engine key"));

        Alert a = new Alert();
        // Sensor attribution comes from the authenticated key only — the
        // body is never consulted, so a client cannot claim another source.
        a.setEngineKey(engineKey);
        a.setThreatType ((String) body.get("threatType"));
        a.setSourceIp   ((String) body.get("sourceIp"));
        a.setSourceMac  ((String) body.get("sourceMac"));
        a.setDestIp     ((String) body.get("destIp"));
        a.setDestMac    ((String) body.get("destMac"));
        a.setProtocol   ((String) body.get("protocol"));
        a.setRequestType((String) body.get("requestType"));
        a.setSeverity   ((String) body.get("severity"));
        a.setDetails    ((String) body.get("details"));
        a.setPacketCount(body.get("packetCount") != null
                ? ((Number) body.get("packetCount")).intValue() : 0);
        a.setWindowMs   (body.get("windowMs") != null
                ? ((Number) body.get("windowMs")).longValue() : 0L);

        // Confidence/provenance metadata — optional so older engine builds
        // (which don't send these fields) keep ingesting cleanly.
        a.setConfidenceScore(body.get("confidenceScore") != null
                ? ((Number) body.get("confidenceScore")).intValue() : null);
        a.setConfidenceReason((String) body.get("confidenceReason"));
        a.setDetectedBy      ((String) body.get("detectedBy"));
        a.setRuleVersion     ((String) body.get("ruleVersion"));
        a.setMitreAttack     ((String) body.get("mitreAttack"));

        String ts = (String) body.get("timestamp");
        if (ts != null) {
            ts = ts.replaceAll("(\\.\\d{3})\\d+", "$1");
            if (!ts.endsWith("Z") && !ts.contains("+")) ts = ts + "Z";
            a.setTimestamp(Instant.parse(ts));
        } else {
            a.setTimestamp(Instant.now());
        }

        return ResponseEntity.ok(alertService.save(a));
    }

    /**
     * Query alerts with optional filters.
     */
    @GetMapping
    public ResponseEntity<?> list(
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String type,
            @RequestParam(required = false) String sourceIp,
            @RequestParam(required = false) String sourceMac,
            @RequestParam(required = false) Long sinceMs) {

        if (severity != null) return ResponseEntity.ok(alertService.getBySeverity(severity));
        if (type     != null) return ResponseEntity.ok(alertService.getByType(type));
        if (sourceIp != null) return ResponseEntity.ok(alertService.getBySourceIp(sourceIp));
        if (sourceMac!= null) return ResponseEntity.ok(alertService.getBySourceMac(sourceMac));
        if (sinceMs  != null) return ResponseEntity.ok(
                alertService.getSince(Instant.ofEpochMilli(sinceMs)));
        return ResponseEntity.ok(alertService.getRecent());
    }

    /**
     * Returns deduplicated AlertSummary rows — what the dashboard table displays.
     * GET /api/alerts/summary
     */
    @GetMapping("/summary")
    public ResponseEntity<?> summary(
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String type) {
        if (severity != null) return ResponseEntity.ok(alertService.getSummariesBySeverity(severity));
        if (type     != null) return ResponseEntity.ok(alertService.getSummariesByType(type));
        return ResponseEntity.ok(alertService.getSummaries());
    }

    /**
     * Dashboard stats — counts from alert_summary, not raw alerts.
     *
     * FIX: was counting from alertRepository (raw events). After deleting a
     * summary row the raw event count never changed, so the counter stayed
     * stale. Now counts from summaryRepository so stats match the table.
     */
    @GetMapping("/stats")
    public ResponseEntity<?> stats() {
        long total    = summaryRepository.count();
        long critical = summaryRepository.countBySeverity("CRITICAL");
        long high     = summaryRepository.countBySeverity("HIGH");
        long medium   = summaryRepository.countBySeverity("MEDIUM");
        return ResponseEntity.ok(Map.of(
            "total",    total,
            "critical", critical,
            "high",     high,
            "medium",   medium));
    }

    /**
     * Delete a single AlertSummary row by its id.
     * DELETE /api/alerts/summaries/{id}
     *
     * FIX: This is the correct endpoint to call when a user dismisses an alert
     * from the dashboard. Deleting from the raw `alerts` table via psql has no
     * effect on the dashboard because the dashboard reads alert_summary, not alerts.
     *
     * After deleting, broadcasts {id} on /topic/alerts/deleted so every connected
     * desktop client removes the row immediately without waiting for the 30-second poll.
     */
    @DeleteMapping("/summaries/{id}")
    public ResponseEntity<?> deleteSummary(@PathVariable Long id) {
        if (!summaryRepository.existsById(id))
            return ResponseEntity.notFound().build();

        summaryRepository.deleteById(id);

        // Notify all live desktop clients instantly
        ws.convertAndSend("/topic/alerts/deleted", Map.of("id", id));

        return ResponseEntity.ok(Map.of("message", "Alert dismissed", "id", id));
    }

    /**
     * Delete ALL AlertSummary rows AND raw alerts.
     * DELETE /api/alerts
     *
     * Broadcasts on /topic/alerts-cleared so live clients wipe their tables.
     */
    // ADMIN only: irreversibly wipes every alert, too destructive for VIEWER.
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping
    public ResponseEntity<?> clearAll() {
        summaryRepository.deleteAll();
        alertRepository.deleteAll();

        ws.convertAndSend("/topic/alerts-cleared", Map.of("cleared", true));

        return ResponseEntity.ok(Map.of("message", "All alerts cleared"));
    }

    /**
     * Analyst verification — mark a raw alert CONFIRMED or FALSE_POSITIVE.
     * PATCH /api/alerts/{id}/verify   body: {"status": "...", "verifiedBy": "..."}
     *
     * False-positive labels accumulate per rule (detectedBy + ruleVersion),
     * giving a measurable precision figure per detector and labelled data
     * for any future ML scoring.
     */
    @PatchMapping("/{id}/verify")
    public ResponseEntity<?> verify(@PathVariable Long id,
                                    @RequestBody Map<String, String> body) {
        String status = body.get("status");
        if (!"CONFIRMED".equals(status) && !"FALSE_POSITIVE".equals(status)
                && !"UNVERIFIED".equals(status)) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "status must be CONFIRMED, FALSE_POSITIVE or UNVERIFIED"));
        }
        return alertRepository.findById(id)
            .map(a -> {
                a.setVerificationStatus(status);
                a.setVerifiedBy(body.getOrDefault("verifiedBy", "analyst"));
                a.setVerifiedAt("UNVERIFIED".equals(status) ? null : Instant.now());
                return ResponseEntity.ok((Object) alertRepository.save(a));
            })
            .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Returns flagged IPs (UNKNOWN_IP / OUTSIDE_SUBNET) deduplicated by sourceIp.
     * GET /api/alerts/flagged-ips
     */
    @GetMapping("/flagged-ips")
    public ResponseEntity<?> flaggedIps() {
        List<Object[]> rows = alertService.getFlaggedIpSummary();
        List<Map<String, Object>> result = new ArrayList<>();
        DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                .withZone(ZoneId.systemDefault());

        // Organization discovery: org_whitelist is the lookup cache — one
        // batch fetch for every flagged IP. Public IPs with no cached row get
        // an async lookup queued (never blocks this request); their name
        // shows as "Unknown" until the next reload finds the cached result.
        List<String> ips = new ArrayList<>();
        for (Object[] row : rows) if (row[0] != null) ips.add(row[0].toString());
        Map<String, OrgWhitelistEntry> orgByIp = orgWhitelistService.getByIps(ips);

        for (Object[] row : rows) {
            // Native query (see findFlaggedIpSummary) returns SQL types:
            // timestamp arrives as java.sql.Timestamp, not Instant.
            Object rawTs = row[5];
            Instant lastSeen = rawTs instanceof java.sql.Timestamp ts
                    ? ts.toInstant() : (Instant) rawTs;
            String severity = switch (((Number) row[6]).intValue()) {
                case 4  -> "CRITICAL";
                case 3  -> "HIGH";
                case 2  -> "MEDIUM";
                case 1  -> "LOW";
                default -> "INFO";
            };

            String ip = row[0] != null ? row[0].toString() : "";
            OrgWhitelistEntry org = orgByIp.get(ip);
            String organization, asn = "", country = "";
            if (org != null && org.getOrgName() != null && !org.getOrgName().isBlank()) {
                // Cached — reuse, never re-query (a cached "Unknown" counts:
                // the lookup already failed once, don't hammer the API).
                organization = org.getOrgName();
                asn     = org.getAsn()     != null ? org.getAsn()     : "";
                country = org.getCountry() != null ? org.getCountry() : "";
            } else if (OrgWhitelistService.isPrivateIp(ip)) {
                // RFC1918/loopback has no owning organization to look up.
                organization = "Private (LAN)";
            } else {
                organization = "Unknown";
                orgWhitelistService.lookupAsync(ip);
            }

            Map<String, Object> entry = new java.util.LinkedHashMap<>();
            entry.put("ip",           ip);
            entry.put("mac",          row[1] != null ? row[1] : "");
            entry.put("threatType",   row[2] != null ? row[2] : "");
            entry.put("protocol",     row[3] != null ? row[3] : "");
            entry.put("hits",         ((Number) row[4]).intValue());
            entry.put("lastSeen",     fmt.format(lastSeen));
            entry.put("severity",     severity);
            entry.put("organization", organization);
            entry.put("asn",          asn);
            entry.put("country",      country);
            result.add(entry);
        }
        return ResponseEntity.ok(result);
    }

    /** IP investigation profile */
    @GetMapping("/ip-profile/{ip}")
    public ResponseEntity<?> ipProfile(@PathVariable String ip) {
        IpProfileDTO profile = alertService.buildIpProfile(ip);
        if (profile == null) return ResponseEntity.notFound().build();
        return ResponseEntity.ok(profile);
    }

    /** Raw alert timeline for a specific IP */
    @GetMapping("/timeline/{ip}")
    public ResponseEntity<?> timeline(@PathVariable String ip) {
        return ResponseEntity.ok(alertService.getBySourceIp(ip));
    }
    /**
     * GET /api/alerts/conversation?ip1=X&ip2=Y
     * Returns every alert between two IPs, either direction, in chronological
     * order. Reuses the same JSON shape as GET /api/alerts so the desktop
     * client's existing alert-parsing code works unchanged.
     */
    @GetMapping("/conversation")
    public ResponseEntity<?> getConversation(@RequestParam String ip1, @RequestParam String ip2) {
        return ResponseEntity.ok(alertRepository.findConversation(ip1, ip2));
    }
}