package com.ids.service;

import com.ids.model.Alert;
import com.ids.repository.AlertRepository;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;
import com.ids.dto.AlertSummaryDTO;
import com.ids.dto.IpProfileDTO;
import java.util.*;
import java.util.stream.Collectors;

import java.time.Instant;
import java.util.*;

@Service
public class AlertService {

    private final AlertRepository       repo;
    private final SimpMessagingTemplate ws;
    private final EmailAlertService     emailService;

    public AlertService(AlertRepository repo,
                        SimpMessagingTemplate ws,
                        EmailAlertService emailService) {
        this.repo         = repo;
        this.ws           = ws;
        this.emailService = emailService;
    }

    // ── Flagged IPs (UNKNOWN_IP / OUTSIDE_SUBNET) ──────────────────────────
    public List<Object[]> getFlaggedIpSummary() {
        return repo.findFlaggedIpSummary();   // ← repo, not alertRepository
    }

    // ── Core alert persistence ──────────────────────────────────────────────
    public Alert save(Alert alert) {
        Alert saved = repo.save(alert);
        ws.convertAndSend("/topic/alerts", saved);
        emailService.sendAlertEmail(saved);
        return saved;
    }

    // ── Queries ─────────────────────────────────────────────────────────────
    public List<Alert> getRecent()               { return repo.findTop100ByOrderByTimestampDesc(); }
    public List<Alert> getBySeverity(String sev) { return repo.findBySeverityOrderByTimestampDesc(sev); }
    public List<Alert> getByType(String type)    { return repo.findByThreatTypeOrderByTimestampDesc(type); }
    public List<Alert> getBySourceIp(String ip)  { return repo.findBySourceIpOrderByTimestampDesc(ip); }
    public List<Alert> getBySourceMac(String mac){ return repo.findBySourceMacOrderByTimestampDesc(mac); }
    public List<Alert> getSince(Instant since)   { return repo.findByTimestampAfterOrderByTimestampDesc(since); }

    // ── Stats ────────────────────────────────────────────────────────────────
    public Map<String, Object> getStats() {
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("total",    repo.count());
        stats.put("critical", repo.countBySeverity("CRITICAL"));
        stats.put("high",     repo.countBySeverity("HIGH"));
        stats.put("medium",   repo.countBySeverity("MEDIUM"));
        stats.put("low",      repo.countBySeverity("LOW"));

        Map<String, Long> byType = new LinkedHashMap<>();
        repo.countByThreatType().forEach(r -> byType.put((String) r[0], (Long) r[1]));
        stats.put("byType", byType);

        Map<String, Long> bySev = new LinkedHashMap<>();
        repo.countBySeverity().forEach(r -> bySev.put((String) r[0], (Long) r[1]));
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
        int raw = (int)(critical * 25 + high * 10 + medium * 3 + low);
        return Math.min(100, raw);
    }

    private String scoreToRisk(int score) {
        if (score >= 75) return "CRITICAL";
        if (score >= 50) return "HIGH";
        if (score >= 25) return "MEDIUM";
        return "LOW";
    }
}