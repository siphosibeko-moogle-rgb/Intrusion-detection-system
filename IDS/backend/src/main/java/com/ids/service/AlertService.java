package com.ids.service;

import com.ids.model.Alert;
import com.ids.model.AlertSummary;
import com.ids.repository.AlertGroupProjection;
import com.ids.repository.AlertRepository;
import com.ids.repository.AlertSummaryRepository;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.ids.dto.AlertSummaryDTO;
import com.ids.dto.IpProfileDTO;
import java.util.*;
import java.util.stream.Collectors;
import java.time.Instant;

@Service
public class AlertService {

    private final AlertRepository        repo;
    private final SimpMessagingTemplate  ws;
    private final EmailAlertService      emailService;
    private final AlertSummaryRepository summaryRepo;
    private final AlertThrottleService   throttle;
    private final OrgWhitelistService    whitelistService;
    private final TrustedCidrRangeService trustedCidrRanges;

    public AlertService(AlertRepository repo,
                        SimpMessagingTemplate ws,
                        EmailAlertService emailService,
                        AlertSummaryRepository summaryRepo,
                        AlertThrottleService throttle,
                        OrgWhitelistService whitelistService,
                        TrustedCidrRangeService trustedCidrRanges) {
        this.repo             = repo;
        this.ws               = ws;
        this.emailService     = emailService;
        this.summaryRepo      = summaryRepo;
        this.throttle         = throttle;
        this.whitelistService = whitelistService;
        this.trustedCidrRanges = trustedCidrRanges;
    }

    // ── Flagged IPs (UNKNOWN_IP / OUTSIDE_SUBNET) ─────────────────────────
    public List<Object[]> getFlaggedIpSummary() {
        return repo.findFlaggedIpSummary();
    }

    // ── Core alert persistence ────────────────────────────────────────────
    /**
     * Ingestion entry point. Alerts from WHITELISTED sources pass through
     * the throttle first; everything else takes the normal path unchanged
     * (evaluate() returns EMIT_LOW without touching the throttle table).
     */
    @Transactional
    public Alert save(Alert alert) {
        switch (throttle.evaluate(alert)) {
            case SUPPRESS -> {
                // Deduped repeat from a trusted host: fold it into the most
                // recent matching open alert — no new row, no broadcast.
                int folded = repo.incrementLatestOccurrence(
                        alert.getSourceIp(), alert.getThreatType(), Instant.now());
                if (folded > 0) return alert;
                // No open alert to fold into (e.g. table was cleared
                // mid-window) — fall through to a normal emit rather than
                // dropping the event on the floor.
                return persistAndBroadcast(alert);
            }
            case ESCALATE -> {
                // The trusted host crossed the threshold: emit ONE new HIGH
                // alert. The throttle guarantees this branch is taken exactly
                // once per window per key.
                return persistAndBroadcast(escalationOf(alert));
            }
            default -> {
                // EMIT_LOW: normal/base severity, normal pipeline.
                return persistAndBroadcast(alert);
            }
        }
    }

    /** Builds the escalated HIGH alert emitted when a trusted source crosses the threshold. */
    private Alert escalationOf(Alert src) {
        Alert esc = new Alert();
        esc.setThreatType (src.getThreatType());
        esc.setSourceIp   (src.getSourceIp());
        esc.setSourceMac  (src.getSourceMac());
        esc.setDestIp     (src.getDestIp());
        esc.setDestMac    (src.getDestMac());
        esc.setProtocol   (src.getProtocol());
        esc.setRequestType(src.getRequestType());
        esc.setPacketCount(src.getPacketCount());
        esc.setWindowMs   (src.getWindowMs());
        esc.setSeverity   ("HIGH");
        esc.setDetails    ("Trusted host " + src.getSourceIp()
                + " crossed the alert-rate threshold for " + src.getThreatType()
                + " — possible compromise. Original: " + src.getDetails());
        esc.setTimestamp  (Instant.now());
        esc.setDetectedBy ("ALERT_THROTTLE");
        esc.setRuleVersion(src.getRuleVersion());
        esc.setMitreAttack(src.getMitreAttack());
        return esc;
    }

    private Alert persistAndBroadcast(Alert alert) {
        // 1. Always persist the raw event — this is what powers the
        //    Investigation Panel (ip-profile / timeline). Unchanged.
        Alert saved = repo.save(alert);

        // 2. Atomically roll it into the summary row the dashboard displays.
        AlertSummary summary = summaryRepo.upsert(
            alert.getSourceIp(), alert.getThreatType(), alert.getSeverity(),
            alert.getSourceMac(), alert.getDestIp(), alert.getDestMac(),
            alert.getProtocol(), alert.getRequestType(), alert.getDetails(),
            alert.getPacketCount(), alert.getWindowMs(), saved.getTimestamp()
        );

        // 3. Broadcast the SUMMARY, not the raw event — this is the actual
        //    fix for the duplicate-row bug. The desktop client now upserts
        //    by (sourceIp, threatType) instead of blindly prepending.
        ws.convertAndSend("/topic/alerts", summary);

        // Only email on the FIRST occurrence — otherwise a sustained scan
        // (re-alerting every ~3s per the engine cooldown) floods the inbox
        // the same way it was flooding the table.
        if (summary.getOccurrenceCount() == 1) {
            emailService.sendAlertEmail(saved);
        }
        return saved;
    }

    // ── Queries ──────────────────────────────────────────────────────────
    // Capped (newest-first, so the cap drops the OLDEST rows) — see the
    // repository note on why unbounded reads of the raw alerts table are
    // not allowed.
    public List<Alert> getRecent()               { return repo.findTop100ByOrderByTimestampDesc(); }
    public List<Alert> getBySeverity(String sev) { return repo.findTop500BySeverityOrderByTimestampDesc(sev); }
    public List<Alert> getByType(String type)    { return repo.findTop500ByThreatTypeOrderByTimestampDesc(type); }
    public List<Alert> getBySourceIp(String ip)  { return repo.findTop500BySourceIpOrderByTimestampDesc(ip); }
    public List<Alert> getBySourceMac(String mac){ return repo.findTop500BySourceMacOrderByTimestampDesc(mac); }
    public List<Alert> getSince(Instant since)   { return repo.findTop1000ByTimestampAfterOrderByTimestampDesc(since); }

    public List<AlertSummary> getSummaries() { return summaryRepo.findAllByOrderByLastSeenDesc(); }
    public List<AlertSummary> getSummariesBySeverity(String sev) { return summaryRepo.findBySeverityOrderByLastSeenDesc(sev); }
    public List<AlertSummary> getSummariesByType(String type) { return summaryRepo.findByThreatTypeOrderByLastSeenDesc(type); }

    // ── Stats ────────────────────────────────────────────────────────────
    public Map<String, Object> getStats() {
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("total",    repo.count());
        stats.put("critical", repo.countBySeverity("CRITICAL"));
        stats.put("high",     repo.countBySeverity("HIGH"));
        stats.put("medium",   repo.countBySeverity("MEDIUM"));
        stats.put("low",      repo.countBySeverity("LOW"));
        stats.put("info",     repo.countBySeverity("INFO"));

        Map<String, Long> byType = new LinkedHashMap<>();
        repo.countByThreatType().forEach(r -> byType.put((String) r[0], (Long) r[1]));
        stats.put("byType", byType);

        Map<String, Long> bySev = new LinkedHashMap<>();
        repo.countBySeverityGrouped().forEach(r -> bySev.put((String) r[0], (Long) r[1]));
        stats.put("bySeverity", bySev);

        List<Map<String, Object>> topAttackers = new ArrayList<>();
        repo.topAttackers().stream().limit(10).forEach(r -> {
            Map<String, Object> a = new LinkedHashMap<>();
            a.put("ip",    r[0]);
            a.put("mac",   r[1]);
            a.put("count", r[2]);
            topAttackers.add(a);
        });
        stats.put("topAttackers", topAttackers);
        return stats;
    }

    public IpProfileDTO buildIpProfile(String ip) {
        // One DB call — compute everything from the result in Java.
        // For a single IP, even 10k alerts is fine in memory.
        List<Alert> alerts = repo.findBySourceIpOrderByTimestampAsc(ip);
        if (alerts.isEmpty()) return null;

        Instant firstSeen = alerts.get(0).getTimestamp();
        Instant lastSeen  = alerts.get(alerts.size() - 1).getTimestamp();

        // Most common MAC for this IP (IPs can change MACs via DHCP churn)
        String mac = alerts.stream()
            .map(Alert::getSourceMac)
            .filter(s -> s != null && !s.isBlank())
            .collect(Collectors.groupingBy(s -> s, Collectors.counting()))
            .entrySet().stream()
            .max(Map.Entry.comparingByValue())
            .map(Map.Entry::getKey)
            .orElse("Unknown");

        Set<String> targets = alerts.stream()
            .map(Alert::getDestIp)
            .filter(s -> s != null && !s.isBlank())
            .collect(Collectors.toSet());

        Set<String> protocols = alerts.stream()
            .map(Alert::getProtocol)
            .filter(s -> s != null && !s.isBlank())
            .collect(Collectors.toCollection(LinkedHashSet::new));

        String topThreatType = alerts.stream()
            .collect(Collectors.groupingBy(Alert::getThreatType, Collectors.counting()))
            .entrySet().stream()
            .max(Map.Entry.comparingByValue())
            .map(Map.Entry::getKey)
            .orElse("UNKNOWN");

        String mostTargetedHost = alerts.stream()
            .filter(a -> a.getDestIp() != null && !a.getDestIp().isBlank())
            .collect(Collectors.groupingBy(Alert::getDestIp, Collectors.counting()))
            .entrySet().stream()
            .max(Map.Entry.comparingByValue())
            .map(Map.Entry::getKey)
            .orElse("N/A");

        int threatScore = calculateThreatScore(alerts);
        String riskLevel = scoreToRisk(threatScore);

        // Return the 50 most recent alerts as summaries (reversed: newest first)
        List<AlertSummaryDTO> recentThreats = new ArrayList<>();
        for (int i = alerts.size() - 1; i >= 0 && recentThreats.size() < 50; i--) {
            Alert a = alerts.get(i);
            recentThreats.add(new AlertSummaryDTO(
                a.getId(), a.getThreatType(), a.getSeverity(),
                a.getSourceIp(), a.getDestIp(), a.getProtocol(),
                a.getRequestType(), a.getDetails(),
                a.getPacketCount(), a.getWindowMs(), a.getTimestamp()
            ));
        }

        return new IpProfileDTO(
            ip, mac,
            alerts.size(),
            targets.size(),
            firstSeen, lastSeen,
            topThreatType, mostTargetedHost,
            threatScore, riskLevel,
            new ArrayList<>(protocols),
            recentThreats
        );
    }

    // Why this scoring? It mirrors how SIEM tools weight alerts.
    // CRITICAL = 25pts, HIGH = 10pts, MEDIUM = 3pts, LOW = 1pt.
    // Capped at 100 — an IP with 4 CRITICAL events is already max risk.
    private int calculateThreatScore(List<Alert> alerts) {
        long critical = alerts.stream().filter(a -> "CRITICAL".equals(a.getSeverity())).count();
        long high     = alerts.stream().filter(a -> "HIGH".equals(a.getSeverity())).count();
        long medium   = alerts.stream().filter(a -> "MEDIUM".equals(a.getSeverity())).count();
        long low      = alerts.stream().filter(a -> "LOW".equals(a.getSeverity())).count();
        return threatScore(critical, high, medium, low);
    }

    private int threatScore(long critical, long high, long medium, long low) {
        int raw = (int)(critical * 25 + high * 10 + medium * 3 + low);
        return Math.min(100, raw);
    }

    private String scoreToRisk(int score) {
        if (score >= 75) return "CRITICAL";
        if (score >= 50) return "HIGH";
        if (score >= 25) return "MEDIUM";
        return "LOW";
    }
    @Transactional
    public void clearAll() {
        summaryRepo.deleteAll();   // clears alert_summary
        repo.deleteAll();          // clears alerts
    }

    @Transactional  
    public void clearSummaries() {
        summaryRepo.deleteAll();   // preserves raw alerts for forensic history
    }
    /**
     * Powers the dashboard Threat Actors table.
     *
     * FIX (perf): previously called buildIpProfile() per ranked IP — 1 + N
     * queries, each loading the ENTIRE alert history of exactly the noisiest
     * IPs on every dashboard render. Now four grouped queries total: the
     * ranked groups, severity counts per IP, threat-type counts per IP, and
     * one batched approved-whitelist lookup (trusted-CIDR check stays
     * in-loop since it's in-memory, not a DB call). Scoring formula is
     * unchanged (threatScore(), shared with buildIpProfile()), so both
     * screens still agree.
     */
    public List<Map<String, Object>> getThreatActors(int limit) {
        List<AlertGroupProjection> ranked = repo.findAlertGroupsBySourceIp(); // one row per IP, already correctly aggregated
        if (ranked.size() > limit) ranked = ranked.subList(0, limit);
        if (ranked.isEmpty()) return List.of();

        List<String> ips = ranked.stream()
                .map(AlertGroupProjection::getSourceIp)
                .collect(Collectors.toList());

        // Batch-fetch approved org entries once — avoids the per-row
        // whitelistService.isWhitelisted(ip) N+1 this method used to run.
        Set<String> approved = whitelistService.approvedIpsAmong(ips);

        // ip -> severity -> count
        Map<String, Map<String, Long>> sevCounts = new HashMap<>();
        for (Object[] r : repo.countSeverityBySourceIps(ips)) {
            sevCounts.computeIfAbsent((String) r[0], k -> new HashMap<>())
                     .put((String) r[1], (Long) r[2]);
        }

        // ip -> most frequent threat type
        Map<String, String> topType = new HashMap<>();
        Map<String, Long> topTypeCount = new HashMap<>();
        for (Object[] r : repo.countThreatTypeBySourceIps(ips)) {
            String ip = (String) r[0];
            long count = (Long) r[2];
            if (count > topTypeCount.getOrDefault(ip, 0L)) {
                topTypeCount.put(ip, count);
                topType.put(ip, (String) r[1]);
            }
        }

        List<Map<String, Object>> actors = new ArrayList<>();
        int rank = 1;
        for (AlertGroupProjection row : ranked) {
            String ip = row.getSourceIp();
            Map<String, Long> sev = sevCounts.getOrDefault(ip, Map.of());
            int score = threatScore(
                    sev.getOrDefault("CRITICAL", 0L),
                    sev.getOrDefault("HIGH", 0L),
                    sev.getOrDefault("MEDIUM", 0L),
                    sev.getOrDefault("LOW", 0L));

            Map<String, Object> actor = new LinkedHashMap<>();
            actor.put("rank", rank++);
            actor.put("ip", ip);
            actor.put("threatScore", score);
            actor.put("totalAlerts", row.getAlertCount());
            actor.put("topThreatType", topType.getOrDefault(ip, "UNKNOWN"));
            actor.put("lastSeen", row.getLastSeen());
            actor.put("whitelisted", approved.contains(ip) || trustedCidrRanges.isTrustedRange(ip));
            actors.add(actor);
        }
        return actors;
    }
}