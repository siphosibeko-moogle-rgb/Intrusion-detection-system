package com.ids.controller;

import com.ids.model.Alert;
import com.ids.model.AlertSummary;
import com.ids.model.ForensicCase;
import com.ids.repository.AlertSummaryRepository;
import com.ids.service.AlertService;
import com.ids.service.ForensicCaseService;
import com.ids.service.OrgWhitelistService;

import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.lang.management.ManagementFactory;
import java.io.File;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

/**
 * DashboardController — backs the SOC dashboard screen.
 *
 * DESIGN NOTES (read before extending this):
 *
 * 1. NO NEW TABLES. Everything here is derived from AlertSummary /
 *    ForensicCase / raw Alert rows that already exist. That keeps this
 *    simple, but it means two numbers here are APPROXIMATIONS, not exact:
 *
 *    - "monitoredHosts" = distinct source IPs seen in alert_summary.
 *      That's attacker/traffic-source IPs, NOT "hosts running an agent".
 *      If you later add real agent/device registration, replace this.
 *
 *    - health.packetCapture / health.liveFeed = inferred from how many
 *      seconds ago the last alert was ingested. A quiet network with a
 *      healthy engine looks identical to a dead engine here. This is a
 *      stand-in until the engine module sends a real heartbeat (a tiny
 *      addition: POST /api/dashboard/heartbeat every 10s using the same
 *      X-Engine-Key auth AlertController already validates).
 *
 * 2. Distinct-IP counting is done in Java over summaryRepository.findAll(),
 *    not SQL COUNT(DISTINCT). Fine at hundreds/thousands of rows. If
 *    alert_summary grows past ~100k rows, replace with a native query —
 *    don't reach for that now, it's premature at current scale.
 */
@RestController
@RequestMapping("/api/dashboard")
public class DashboardController {

    private final AlertSummaryRepository summaryRepository;
    private final AlertService alertService;
    private final ForensicCaseService caseService;
    private final OrgWhitelistService whitelistService;
    private final JdbcTemplate jdbcTemplate; // used only for a DB health ping

    public DashboardController(AlertSummaryRepository summaryRepository,
                                AlertService alertService,
                                ForensicCaseService caseService,
                                OrgWhitelistService whitelistService,
                                JdbcTemplate jdbcTemplate) {
        this.summaryRepository = summaryRepository;
        this.alertService = alertService;
        this.caseService = caseService;
        this.whitelistService = whitelistService;
        this.jdbcTemplate = jdbcTemplate;
    }
    @GetMapping("/threat-actors")
    public ResponseEntity<?> threatActors(
            @RequestParam(required = false, defaultValue = "15") int limit) {
        return ResponseEntity.ok(alertService.getThreatActors(limit));
    }
    // ── SUMMARY ─────────────────────────────────────────────────────────

    @GetMapping("/summary")
    public Map<String, Object> summary() {
        List<AlertSummary> allSummaries = summaryRepository.findAllByOrderByLastSeenDesc();

        long total = allSummaries.size();
        long critical = allSummaries.stream().filter(a -> "CRITICAL".equalsIgnoreCase(a.getSeverity())).count();
        long high     = allSummaries.stream().filter(a -> "HIGH".equalsIgnoreCase(a.getSeverity())).count();
        long medium   = allSummaries.stream().filter(a -> "MEDIUM".equalsIgnoreCase(a.getSeverity())).count();
        long low      = allSummaries.stream().filter(a -> "LOW".equalsIgnoreCase(a.getSeverity())).count();

        long monitoredHosts = allSummaries.stream()
                .map(AlertSummary::getSourceIp)
                .filter(Objects::nonNull)
                .distinct()
                .count();

        List<ForensicCase> cases = caseService.getAll();
        long openCases = cases.stream()
                .filter(c -> c.getStatus() != null && c.getStatus().toUpperCase().contains("OPEN"))
                .count();
        long investigatingCases = cases.stream()
                .filter(c -> c.getStatus() != null &&
                        (c.getStatus().toUpperCase().contains("PROGRESS")
                                || c.getStatus().toUpperCase().contains("INVESTIGAT")))
                .count();

        // Recent alerts — top 8 for the "Recent Alerts" table
        List<Map<String, Object>> recent = allSummaries.stream()
                .limit(8)
                .map(this::toAlertRow)
                .collect(Collectors.toList());

        // Recent cases — top 6 for "Recent Investigations"
        List<Map<String, Object>> recentCases = cases.stream()
                .sorted((a, b) -> {
                    Instant ta = a.getOpenedAt() != null ? a.getOpenedAt() : Instant.EPOCH;
                    Instant tb = b.getOpenedAt() != null ? b.getOpenedAt() : Instant.EPOCH;
                    return tb.compareTo(ta);
                })
                .limit(6)
                .map(this::toCaseRow)
                .collect(Collectors.toList());

        // Alert activity — last hour, 5-minute buckets, from RAW alerts
        // (raw, not summary, because summary collapses repeats — the line
        // graph needs to show actual event volume over time).
        List<Map<String, Object>> activity = buildActivityBuckets();

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("activeAlerts", total);
        out.put("criticalThreats", critical);
        out.put("openCases", openCases);
        out.put("investigatingCases", investigatingCases);
        out.put("monitoredHosts", monitoredHosts);
        out.put("severityDistribution", Map.of(
                "CRITICAL", critical, "HIGH", high, "MEDIUM", medium, "LOW", low));
        out.put("recentAlerts", recent);
        out.put("recentCases", recentCases);
        out.put("activity", activity);
        return out;
    }

    private List<Map<String, Object>> buildActivityBuckets() {
        Instant cutoff = Instant.now().minus(1, ChronoUnit.HOURS);
        List<Alert> recentRaw;
        try {
            recentRaw = alertService.getSince(cutoff);
        } catch (Exception e) {
            return List.of();
        }

        // 12 buckets of 5 minutes = 1 hour
        Instant now = Instant.now();
        Map<Long, long[]> buckets = new TreeMap<>(); // bucketIndex -> [total, critical]
        for (int i = 0; i < 12; i++) buckets.put((long) i, new long[]{0, 0});

        for (Alert a : recentRaw) {
            if (a.getTimestamp() == null) continue;
            long minutesAgo = ChronoUnit.MINUTES.between(a.getTimestamp(), now);
            long bucketFromEnd = minutesAgo / 5; // 0 = most recent 5-min window
            long bucketIndex = 11 - bucketFromEnd;
            if (bucketIndex < 0 || bucketIndex > 11) continue;
            long[] counts = buckets.get(bucketIndex);
            counts[0]++;
            if ("CRITICAL".equalsIgnoreCase(a.getSeverity())) counts[1]++;
        }

        List<Map<String, Object>> result = new ArrayList<>();
        for (Map.Entry<Long, long[]> e : buckets.entrySet()) {
            Instant bucketTime = now.minus((11 - e.getKey()) * 5L, ChronoUnit.MINUTES);
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("time", bucketTime.toString());
            row.put("total", e.getValue()[0]);
            row.put("critical", e.getValue()[1]);
            result.add(row);
        }
        return result;
    }

    private Map<String, Object> toAlertRow(AlertSummary a) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("timestamp", a.getLastSeen() != null ? a.getLastSeen().toString() : "");
        row.put("severity", a.getSeverity());
        row.put("threatType", a.getThreatType());
        row.put("sourceIp", a.getSourceIp());
        row.put("destIp", a.getDestIp());
        row.put("protocol", a.getProtocol());
        row.put("whitelisted", whitelistService.isWhitelisted(a.getSourceIp()));
        return row;
    }

    private Map<String, Object> toCaseRow(ForensicCase c) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("caseNumber", c.getCaseNumber());
        row.put("title", c.getTitle());
        row.put("priority", c.getPriority());
        row.put("status", c.getStatus());
        row.put("openedAt", c.getOpenedAt() != null ? c.getOpenedAt().toString() : "");
        row.put("assignedTo", c.getAssignedTo());
        return row;
    }

    // ── SYSTEM HEALTH ───────────────────────────────────────────────────

    @GetMapping("/health")
    public Map<String, Object> health() {
        Map<String, Object> out = new LinkedHashMap<>();

        // Backend: if this method is executing, the backend is up.
        out.put("backendApi", status(true, null));

        // Database: a trivial round-trip query. If this throws, DB is down.
        boolean dbUp = true;
        try {
            jdbcTemplate.queryForObject("SELECT 1", Integer.class);
        } catch (Exception e) {
            dbUp = false;
        }
        out.put("database", status(dbUp, null));

        // CPU / RAM — java.lang.management, no extra dependency needed.
        double cpuPct = -1, ramPct = -1;
        try {
            com.sun.management.OperatingSystemMXBean osBean =
                    (com.sun.management.OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
            cpuPct = osBean.getCpuLoad() * 100.0; // JDK 17+; -1 if not yet available
            long total = osBean.getTotalMemorySize();
            long free = osBean.getFreeMemorySize();
            if (total > 0) ramPct = ((double) (total - free) / total) * 100.0;
        } catch (Exception ignored) {
            // Some JVMs / containers restrict this MXBean cast — degrade gracefully.
        }
        out.put("cpuUsagePct", round1(cpuPct));
        out.put("ramUsagePct", round1(ramPct));
        out.put("cpu", thresholdStatus(cpuPct, 70, 90));
        out.put("ram", thresholdStatus(ramPct, 75, 90));

        // Disk — root filesystem usage.
        File root = new File("/");
        double diskPct = -1;
        long totalSpace = root.getTotalSpace();
        if (totalSpace > 0) {
            diskPct = ((double) (totalSpace - root.getUsableSpace()) / totalSpace) * 100.0;
        }
        out.put("diskUsagePct", round1(diskPct));
        out.put("disk", thresholdStatus(diskPct, 80, 95));

        // Packet capture / live feed — PROXY based on last alert recency.
        // See class-level javadoc: this is not a real heartbeat.
        // Reuses getRecent() (already used by AlertController's default GET
        // /api/alerts) instead of adding a new AlertService method just for
        // this — getRecent() is assumed to return newest-first.
        Instant lastAlert = null;
        try {
            List<Alert> recent = alertService.getRecent();
            if (recent != null && !recent.isEmpty()) {
                lastAlert = recent.get(0).getTimestamp();
            }
        } catch (Exception ignored) {
        }
        String captureStatus;
        if (lastAlert == null) {
            captureStatus = "WARN"; // never received anything since startup
        } else {
            long secondsAgo = ChronoUnit.SECONDS.between(lastAlert, Instant.now());
            captureStatus = secondsAgo < 300 ? "OK" : (secondsAgo < 1800 ? "WARN" : "ERROR");
        }
        out.put("packetCapture", Map.of("status", captureStatus, "note", "proxy: time since last alert"));
        out.put("liveFeed", Map.of("status", captureStatus, "note", "proxy: time since last alert"));

        return out;
    }

    private Map<String, Object> status(boolean ok, String detail) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", ok ? "OK" : "ERROR");
        if (detail != null) m.put("detail", detail);
        return m;
    }

    private Map<String, Object> thresholdStatus(double pct, double warnAt, double errorAt) {
        String s;
        if (pct < 0) s = "UNKNOWN";
        else if (pct >= errorAt) s = "ERROR";
        else if (pct >= warnAt) s = "WARN";
        else s = "OK";
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("status", s);
        m.put("value", round1(pct));
        return m;
    }

    private double round1(double v) {
        if (v < 0) return -1;
        return Math.round(v * 10.0) / 10.0;
    }
}