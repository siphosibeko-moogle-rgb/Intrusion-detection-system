package com.ids.controller;

import com.ids.model.Alert;
import com.ids.service.AlertService;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.ids.repository.AlertRepository;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Map;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import com.ids.dto.AlertSummaryDTO;
import com.ids.dto.IpProfileDTO;

@RestController
@RequestMapping("/api/alerts")
public class AlertController {
	
    @Value("${ids.engine.apikey}")
    private String engineApiKey;

    private final AlertService alertService;
    private final AlertRepository alertRepository;

    public AlertController(AlertService alertService,AlertRepository alertRepository) {
		this.alertService    = alertService;
		this.alertRepository = alertRepository;
}

    /**
     * Engine posts alerts here — validated by X-Engine-Key header.
     * No JWT required — uses a shared API key instead.
     */
    @PostMapping("/ingest")
    public ResponseEntity<?> ingest(@RequestHeader("X-Engine-Key") String key,
                                    @RequestBody Map<String, Object> body) {
        if (!engineApiKey.equals(key))
            return ResponseEntity.status(403).body(Map.of("error", "Invalid engine key"));

        Alert a = new Alert();
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
        String ts = (String) body.get("timestamp");
        if (ts != null) {
            ts = ts.replaceAll("(\\.\\d{3})\\d+", "$1");
            if (!ts.endsWith("Z") && !ts.contains("+")) ts = ts + "Z";
            a.setTimestamp(Instant.parse(ts));
        } else  {
            a.setTimestamp(Instant.now());
        }

        return ResponseEntity.ok(alertService.save(a));  // ← this line is missing
    }

    /**
     * Query alerts with optional filters.
     * GET /api/alerts
     * GET /api/alerts?severity=CRITICAL
     * GET /api/alerts?type=NMAP_SYN_SCAN
     * GET /api/alerts?sourceIp=192.168.1.45
     * GET /api/alerts?sourceMac=aa:bb:cc:dd:ee:ff
     * GET /api/alerts?sinceMs=1700000000000
     */
    @GetMapping
    public ResponseEntity<?> list(
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String type,
            @RequestParam(required = false) String sourceIp,
            @RequestParam(required = false) String sourceMac,
            @RequestParam(required = false) Long   sinceMs) {

        if (severity  != null) return ResponseEntity.ok(alertService.getBySeverity(severity));
        if (type      != null) return ResponseEntity.ok(alertService.getByType(type));
        if (sourceIp  != null) return ResponseEntity.ok(alertService.getBySourceIp(sourceIp));
        if (sourceMac != null) return ResponseEntity.ok(alertService.getBySourceMac(sourceMac));
        if (sinceMs   != null) return ResponseEntity.ok(
            alertService.getSince(Instant.ofEpochMilli(sinceMs)));
        return ResponseEntity.ok(alertService.getRecent());
    }

    /** Dashboard stats: totals, byType, bySeverity, topAttackers */
    @GetMapping("/stats")
    public ResponseEntity<?> stats() {
        long total    = alertRepository.count();
        long critical = alertRepository.countBySeverity("CRITICAL");
        long high     = alertRepository.countBySeverity("HIGH");
        long medium   = alertRepository.countBySeverity("MEDIUM");
        return ResponseEntity.ok(Map.of(
            "total", total, 
            "critical", critical,
            "high", high, 
            "medium", medium));
    }
    /**
     * Returns flagged IPs (UNKNOWN_IP / OUTSIDE_SUBNET) deduplicated by sourceIp.
     * Used by the Whitelist tab "Flagged IPs" section.
     * GET /api/alerts/flagged-ips
     */
    @GetMapping("/flagged-ips")
    public ResponseEntity<?> flaggedIps() {
        List<Object[]> rows = alertService.getFlaggedIpSummary();
        List<Map<String, Object>> result = new ArrayList<>();
        DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                .withZone(ZoneId.systemDefault());
        for (Object[] row : rows) {
            result.add(Map.of(
                "ip",         row[0] != null ? row[0] : "",
                "mac",        row[1] != null ? row[1] : "",
                "threatType", row[2] != null ? row[2] : "",
                "protocol",   row[3] != null ? row[3] : "",
                "hits",       ((Number) row[4]).intValue(),
                "lastSeen",   fmt.format((Instant) row[5])
            ));
        }
        return ResponseEntity.ok(result);
    }
    @GetMapping("/ip-profile/{ip}")
    public ResponseEntity<?> ipProfile(@PathVariable String ip) {
        IpProfileDTO profile = alertService.buildIpProfile(ip);
        if (profile == null)
            return ResponseEntity.notFound().build();
        return ResponseEntity.ok(profile);
    }
    public ResponseEntity<?> timeline(@PathVariable String ip) {
        List<Alert> alerts = alertRepository.findBySourceIpOrderByTimestampAsc(ip);
        List<AlertSummaryDTO> result = alerts.stream().map(a -> new AlertSummaryDTO(
            a.getId(), a.getThreatType(), a.getSeverity(),
            a.getSourceIp(), a.getDestIp(), a.getProtocol(),
            a.getRequestType(), a.getDetails(),
            a.getPacketCount(), a.getWindowMs(), a.getTimestamp()
        )).toList();
        return ResponseEntity.ok(result);
    }
    @GetMapping("/summary")
    public ResponseEntity<?> summary(
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String type) {
        if (severity != null) return ResponseEntity.ok(alertService.getSummariesBySeverity(severity));
        if (type != null)     return ResponseEntity.ok(alertService.getSummariesByType(type));
        return ResponseEntity.ok(alertService.getSummaries());
    }
}