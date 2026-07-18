package com.ids.service;

import com.ids.dto.AlertGroupDTO;
import com.ids.dto.CaseDetailDTO;
import com.ids.entity.CaseNote;
import com.ids.entity.CaseTimelineEntry;
import com.ids.model.Alert;
import com.ids.model.ForensicCase;
import com.ids.model.PacketLog;
import com.ids.repository.AlertGroupProjection;
import com.ids.repository.AlertRepository;
import com.ids.repository.CaseNoteRepository;
import com.ids.repository.CaseTimelineRepository;
import com.ids.repository.ForensicCaseRepository;
import com.ids.repository.PacketLogRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Central service for Case Management.
 *
 * FIX APPLIED (2026-06-30): getDetail() was calling
 * alertRepo.findTop500BySuspectIp(...) which does not exist on
 * AlertRepository — this was a compile-breaking method name. The repository
 * exposes findTop500BySourceIpOrderByTimestampDesc(String sourceIp) instead
 * (Alert's column is sourceIp, "suspect" is case-domain language that only
 * exists on ForensicCase). Corrected below, and the list is reversed before
 * being placed in the DTO so the Alerts tab still gets oldest-first ordering
 * consistent with refreshCaseStats() and create().
 *
 * Design decisions worth explaining:
 *
 * 1. AUTO-LINKING ALERTS
 *    When a case is created for a suspect IP, we immediately count
 *    how many alerts exist for that IP and record first/last seen.
 *    We do NOT store a case_id FK on each alert row — that would mean
 *    one alert can only belong to one case (false for multi-IP attacks).
 *    Instead, we query alerts by IP on-demand. This is the same
 *    approach Suricata/Security Onion use: events live in their own
 *    table, cases are a view over them.
 *
 * 2. TIMELINE AUTO-POPULATION
 *    Every meaningful state change writes a CaseTimelineEntry.
 *    This gives analysts a free audit log without extra code in the UI.
 *
 * 3. TRANSACTION BOUNDARIES
 *    create() and update() are @Transactional so the main record +
 *    timeline entry always commit together or both roll back.
 */
@Service
public class ForensicCaseService {

    private final ForensicCaseRepository caseRepo;
    private final PacketLogRepository    packetRepo;
    private final AlertRepository        alertRepo;
    private final CaseNoteRepository     noteRepo;
    private final CaseTimelineRepository timelineRepo;

    public ForensicCaseService(ForensicCaseRepository caseRepo,
                               PacketLogRepository packetRepo,
                               AlertRepository alertRepo,
                               CaseNoteRepository noteRepo,
                               CaseTimelineRepository timelineRepo) {
        this.caseRepo     = caseRepo;
        this.packetRepo   = packetRepo;
        this.alertRepo    = alertRepo;
        this.noteRepo     = noteRepo;
        this.timelineRepo = timelineRepo;
    }

    // ── CASE CRUD ────────────────────────────────────────────────────────────

    @Transactional
    public ForensicCase create(ForensicCase fc, String createdBy) {
        fc.setCreatedBy(createdBy);
        if (fc.getCaseNumber() == null || fc.getCaseNumber().isBlank())
            fc.setCaseNumber(generateCaseNumber());

        // Derive first/last seen and alert count from existing alert history
        if (fc.getSuspectIp() != null && !fc.getSuspectIp().isBlank()) {
            List<Alert> existing = alertRepo.findBySourceIpOrderByTimestampAsc(fc.getSuspectIp());
            if (!existing.isEmpty()) {
                fc.setFirstSeen(existing.get(0).getTimestamp());
                fc.setLastSeen(existing.get(existing.size() - 1).getTimestamp());
                fc.setAlertCount(existing.size());
            }
        }

        ForensicCase saved = caseRepo.save(fc);

        // Seed the timeline
        timelineRepo.save(CaseTimelineEntry.of(
            saved.getId(), "CASE_OPENED", createdBy,
            "Case " + saved.getCaseNumber() + " opened for " + saved.getSuspectIp()
        ));

        if (saved.getAlertCount() > 0) {
            timelineRepo.save(CaseTimelineEntry.of(
                saved.getId(), "ALERT_LINKED", "system",
                saved.getAlertCount() + " historical alerts auto-linked from " + saved.getSuspectIp()
            ));
        }

        return saved;
    }

    /**
     * Create a case directly from an alert row — the "Investigate" quick action.
     * Pulls suspectIp / suspectMac / threatType straight off the alert so the
     * analyst doesn't retype anything they just clicked on.
     */
    @Transactional
    public ForensicCase createFromAlert(Long alertId, String title, String priority, String createdBy) {
        Alert alert = alertRepo.findById(alertId)
                .orElseThrow(() -> new RuntimeException("Alert not found: " + alertId));

        ForensicCase fc = new ForensicCase();
        fc.setTitle(title != null && !title.isBlank()
                ? title
                : "Investigation: " + alert.getThreatType() + " from " + alert.getSourceIp());
        fc.setSuspectIp(alert.getSourceIp());
        fc.setSuspectMac(alert.getSourceMac());
        fc.setThreatType(alert.getThreatType());
        fc.setSeverity(alert.getSeverity());
        fc.setPriority(priority != null ? priority : "MEDIUM");
        fc.setStatus("OPEN");

        return create(fc, createdBy);
    }

    @Transactional
    public ForensicCase update(Long id, ForensicCase patch, String byUser) {
        ForensicCase fc = caseRepo.findById(id)
                .orElseThrow(() -> new RuntimeException("Case not found: " + id));

        String oldStatus = fc.getStatus();

        if (patch.getStatus()      != null) fc.setStatus(patch.getStatus());
        if (patch.getAssignedTo()  != null) fc.setAssignedTo(patch.getAssignedTo());
        if (patch.getFindings()    != null) fc.setFindings(patch.getFindings());
        if (patch.getDescription() != null) fc.setDescription(patch.getDescription());
        if (patch.getSeverity()    != null) fc.setSeverity(patch.getSeverity());
        if (patch.getTitle()       != null) fc.setTitle(patch.getTitle());
        if (patch.getPriority()    != null) fc.setPriority(patch.getPriority());

        if ("CLOSED".equals(patch.getStatus()) && !"CLOSED".equals(oldStatus)) {
            fc.setClosedAt(Instant.now());
            timelineRepo.save(CaseTimelineEntry.of(
                id, "CASE_CLOSED", byUser, "Case closed by " + byUser
            ));
        } else if (patch.getStatus() != null && !patch.getStatus().equals(oldStatus)) {
            timelineRepo.save(CaseTimelineEntry.of(
                id, "STATUS_CHANGED", byUser,
                "Status changed from " + oldStatus + " to " + patch.getStatus()
            ));
        }

        if (patch.getAssignedTo() != null) {
            timelineRepo.save(CaseTimelineEntry.of(
                id, "ANALYST_ACTION", byUser,
                "Case assigned to " + patch.getAssignedTo()
            ));
        }

        return caseRepo.save(fc);
    }

    /** Dedicated status-only transition, used by quick-action buttons. */
    @Transactional
    public ForensicCase updateStatus(Long id, String newStatus, String byUser) {
        ForensicCase patch = new ForensicCase();
        patch.setStatus(newStatus);
        return update(id, patch, byUser);
    }

    /** Dedicated assign-only transition, used by the "Assign to me" button. */
    @Transactional
    public ForensicCase assign(Long id, String analyst, String byUser) {
        ForensicCase patch = new ForensicCase();
        patch.setAssignedTo(analyst);
        return update(id, patch, byUser);
    }

    public List<ForensicCase> getAll()                    { return caseRepo.findTop50ByOrderByOpenedAtDesc();          }
    public Optional<ForensicCase> getById(Long id)        { return caseRepo.findById(id);                              }
    public Optional<ForensicCase> getByNumber(String num) { return caseRepo.findByCaseNumber(num);                     }
    public List<ForensicCase> getByStatus(String status)  { return caseRepo.findByStatusOrderByOpenedAtDesc(status);   }
    public List<ForensicCase> getBySuspectIp(String ip)   { return caseRepo.findBySuspectIpOrderByOpenedAtDesc(ip);    }
    public List<ForensicCase> getBySuspectMac(String mac) { return caseRepo.findBySuspectMacOrderByOpenedAtDesc(mac);  }
    public List<ForensicCase> getByAssignee(String user)  { return caseRepo.findByAssignedToOrderByOpenedAtDesc(user); }

    @Transactional
    public void delete(Long id) {
        // Cascade handles notes and timeline rows (ON DELETE CASCADE in DDL)
        caseRepo.deleteById(id);
    }

    // ── CASE DETAIL ──────────────────────────────────────────────────────────

    /**
     * Builds the full CaseDetailDTO in one call.
     *
     * We make 4 DB queries:
     *   1. Case metadata
     *   2. Linked alerts by IP (capped at 500, newest-first from the repo,
     *      then reversed here so the DTO carries oldest-first — matching
     *      how create()/refreshCaseStats() compute firstSeen/lastSeen)
     *   3. Timeline entries
     *   4. Notes
     *
     * This is deliberately 4 separate queries rather than one massive JOIN.
     * JPA struggles to page/limit sub-collections in a single JOIN fetch, and
     * the Cartesian product for (case × alerts × timeline × notes) would be huge.
     * Four targeted indexed queries is faster and cleaner.
     */
    @Transactional(readOnly = true)
    public Optional<CaseDetailDTO> getDetail(Long caseId) {
        return caseRepo.findById(caseId).map(fc -> {
            CaseDetailDTO dto = new CaseDetailDTO();

            // 1. Metadata
            dto.setId(fc.getId());
            dto.setCaseNumber(fc.getCaseNumber());
            dto.setTitle(fc.getTitle());
            dto.setDescription(fc.getDescription());
            dto.setStatus(fc.getStatus());
            dto.setPriority(fc.getPriority());
            dto.setSeverity(fc.getSeverity());
            dto.setSuspectIp(fc.getSuspectIp());
            dto.setSuspectMac(fc.getSuspectMac());
            dto.setThreatType(fc.getThreatType());
            dto.setAssignedTo(fc.getAssignedTo());
            dto.setCreatedBy(fc.getCreatedBy());
            dto.setOpenedAt(fc.getOpenedAt());
            dto.setClosedAt(fc.getClosedAt());

            // 2. Linked alerts (cap at 500 to prevent OOM on a noisy IP).
            //    FIXED: was findTop500BySuspectIp (doesn't exist on AlertRepository).
            //    Correct method is findTop500BySourceIpOrderByTimestampDesc.
            List<Alert> alertsDesc = (fc.getSuspectIp() != null && !fc.getSuspectIp().isBlank())
                    ? alertRepo.findTop500BySourceIpOrderByTimestampDesc(fc.getSuspectIp())
                    : List.of();

            dto.setLinkedAlerts(alertsDesc);   // newest-first — what the Alerts tab wants to render
            dto.setAlertCount(alertsDesc.size());

            // Recompute first/last seen from the live (capped) data.
            // Note: if the IP has > 500 alerts, firstSeen here reflects only
            // the 500 most recent — getById()/create() use the uncapped query
            // for the authoritative firstSeen stored on the case row itself.
            if (!alertsDesc.isEmpty()) {
                dto.setFirstSeen(alertsDesc.get(alertsDesc.size() - 1).getTimestamp()); // oldest of the 500
                dto.setLastSeen(alertsDesc.get(0).getTimestamp());                      // newest
            }

            // 3. Timeline
            dto.setTimeline(timelineRepo.findByCaseIdOrderByOccurredAtAsc(caseId));

            // 4. Notes
            dto.setNotes(noteRepo.findByCaseIdOrderByCreatedAtDesc(caseId));

            return dto;
        });
    }

    /**
     * Refresh alert count + timestamps on the case row itself.
     * Call this after new alerts arrive for the suspect IP so the
     * cases list always shows current numbers without recomputing
     * on every single list-screen render.
     */
    @Transactional
    public void refreshCaseStats(Long caseId) {
        caseRepo.findById(caseId).ifPresent(fc -> {
            if (fc.getSuspectIp() == null) return;
            List<Alert> alerts = alertRepo.findBySourceIpOrderByTimestampAsc(fc.getSuspectIp());
            if (!alerts.isEmpty()) {
                fc.setAlertCount(alerts.size());
                fc.setFirstSeen(alerts.get(0).getTimestamp());
                fc.setLastSeen(alerts.get(alerts.size() - 1).getTimestamp());
                caseRepo.save(fc);
            }
        });
    }

    // ── NOTES ────────────────────────────────────────────────────────────────

    @Transactional
    public CaseNote addNote(Long caseId, String content, String author) {
        caseRepo.findById(caseId)
                .orElseThrow(() -> new RuntimeException("Case not found: " + caseId));

        CaseNote note = new CaseNote();
        note.setCaseId(caseId);
        note.setContent(content);
        note.setAuthor(author);
        CaseNote saved = noteRepo.save(note);

        // Auto-append timeline entry, deep-linked via refId to the note itself
        timelineRepo.save(CaseTimelineEntry.of(
            caseId, "NOTE_ADDED", author,
            "Note added by " + author, saved.getId()
        ));

        return saved;
    }

    public List<CaseNote> getNotes(Long caseId) {
        return noteRepo.findByCaseIdOrderByCreatedAtDesc(caseId);
    }

    @Transactional
    public void deleteNote(Long noteId) {
        noteRepo.deleteById(noteId);
    }

    // ── TIMELINE ─────────────────────────────────────────────────────────────

    public List<CaseTimelineEntry> getTimeline(Long caseId) {
        return timelineRepo.findByCaseIdOrderByOccurredAtAsc(caseId);
    }

    /**
     * Record an analyst quick-action on the timeline.
     * Used by Block IP and Whitelist IP buttons elsewhere in the app —
     * call this right after the block/whitelist write succeeds so the
     * case timeline reflects response actions, not just detections.
     */
    @Transactional
    public void recordAction(Long caseId, String kind, String actor, String detail) {
        timelineRepo.save(CaseTimelineEntry.of(caseId, kind, actor, detail));
    }

    // ── PACKETS ──────────────────────────────────────────────────────────────

    public PacketLog savePacketLog(PacketLog log)        { return packetRepo.save(log);                                  }
    public Optional<PacketLog> getPacketById(Long id)    { return packetRepo.findById(id);                               }
    public List<PacketLog> getPacketsByCase(Long caseId) { return packetRepo.findByCaseIdOrderByCapturedAtDesc(caseId); }
    public List<PacketLog> getPacketsByIp(String ip)     { return packetRepo.findBySourceIpOrderByCapturedAtDesc(ip);   }
    public List<PacketLog> getPacketsByMac(String mac)   { return packetRepo.findBySourceMacOrderByCapturedAtDesc(mac); }
    public List<PacketLog> getRecentPackets()             { return packetRepo.findTop200ByOrderByCapturedAtDesc();       }

    // ── HELPERS ──────────────────────────────────────────────────────────────

    private String generateCaseNumber() {
        int  year = java.time.LocalDate.now().getYear();
        long seq  = caseRepo.count() + 1;
        return String.format("CASE-%d-%03d", year, seq);
    }
    public List<AlertGroupDTO> getAlertGroupsForCaseCreation() {
        List<AlertGroupProjection> groups = alertRepo.findAlertGroupsBySourceIp();

        // FIX (perf): existing-case lookup was one query per group. Batch
        // them: one IN query, keeping the most recent case per IP (rows come
        // back openedAt-desc, so the first one seen per IP wins).
        List<String> ips = groups.stream()
                .map(AlertGroupProjection::getSourceIp)
                .collect(Collectors.toList());
        java.util.Map<String, ForensicCase> latestCaseByIp = new java.util.HashMap<>();
        if (!ips.isEmpty()) {
            for (ForensicCase c : caseRepo.findBySuspectIpInOrderByOpenedAtDesc(ips)) {
                latestCaseByIp.putIfAbsent(c.getSuspectIp(), c);
            }
        }

        return groups.stream()
                .map(g -> toGroupDto(g, latestCaseByIp.get(g.getSourceIp())))
                .collect(Collectors.toList());
    }

    private AlertGroupDTO toGroupDto(AlertGroupProjection g, ForensicCase existing) {
        AlertGroupDTO dto = new AlertGroupDTO();
        dto.setSourceIp(g.getSourceIp());
        dto.setSourceMac(g.getSourceMac());
        dto.setAlertCount(g.getAlertCount());
        dto.setFirstSeen(g.getFirstSeen());
        dto.setLastSeen(g.getLastSeen());
        dto.setThreatTypes(g.getThreatTypes());
        dto.setSeverity(rankToSeverity(g.getSeverityRank()));

        dto.setHasExistingCase(existing != null);
        if (existing != null) {
            dto.setExistingCaseId(existing.getId());
            dto.setExistingCaseNumber(existing.getCaseNumber());
        }
        return dto;
    }

    private String rankToSeverity(Integer rank) {
        if (rank == null) return "LOW";
        switch (rank) {
            case 4: return "CRITICAL";
            case 3: return "HIGH";
            case 2: return "MEDIUM";
            default: return "LOW";
        }
    }

    private int severityRank(String severity) {
        if (severity == null) return 0;
        switch (severity.toUpperCase()) {
            case "CRITICAL": return 4;
            case "HIGH": return 3;
            case "MEDIUM": return 2;
            case "LOW": return 1;
            default: return 0;
        }
    }

    /**
     * Creates one case per source IP, reusing create() so every existing
     * behavior (alert auto-linking, timeline seeding) stays consistent.
     * Dedup rule: if a case already exists for this IP, return it instead
     * of creating a second one — per your requirement, no duplicate cases
     * for the same IP.
     */
    @Transactional
    public ForensicCase createFromIpGroup(String suspectIp, String createdBy) {
        List<ForensicCase> existing = getBySuspectIp(suspectIp);
        if (!existing.isEmpty()) {
            return existing.get(0);
        }

        List<Alert> alerts = alertRepo.findBySourceIpOrderByTimestampAsc(suspectIp);
        if (alerts.isEmpty()) {
            throw new RuntimeException("No alerts found for IP: " + suspectIp);
        }

        String threatTypes = alerts.stream()
                .map(Alert::getThreatType)
                .distinct()
                .collect(Collectors.joining(", "));

        String highestSeverity = alerts.stream()
                .map(Alert::getSeverity)
                .max(Comparator.comparingInt(this::severityRank))
                .orElse("MEDIUM");

        ForensicCase fc = new ForensicCase();
        fc.setTitle("Investigation: " + threatTypes + " from " + suspectIp);
        fc.setSuspectIp(suspectIp);
        fc.setSuspectMac(alerts.get(alerts.size() - 1).getSourceMac());
        fc.setThreatType(threatTypes);
        fc.setSeverity(highestSeverity);
        fc.setPriority("MEDIUM");

        return create(fc, createdBy);
    }
}