package com.ids.service;

import com.ids.model.Alert;
import com.ids.repository.AlertRepository;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

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
}