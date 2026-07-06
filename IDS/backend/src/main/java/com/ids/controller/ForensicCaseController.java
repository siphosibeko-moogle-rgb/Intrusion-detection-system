package com.ids.controller;

import com.ids.entity.CaseNote;
import com.ids.model.ForensicCase;
import com.ids.model.PacketLog;
import com.ids.service.ForensicCaseService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Value;

import java.util.Map;

/**
 * UPDATED 2026-06-30: the original controller only exposed case CRUD and
 * packet endpoints. ForensicCaseService already had getDetail(), addNote(),
 * getTimeline(), and recordAction() implemented — they were just never wired
 * to a route. This update adds those routes plus two new quick-action
 * endpoints (status, assign) and a "create case from alert" endpoint that
 * the Investigate button on the Alerts tab needs.
 *
 * Everything below the "── PACKETS ──" marker is unchanged from the original.
 */
@RestController
@RequestMapping("/api/forensics")
public class ForensicCaseController {

    @Value("${ids.engine.apikey}")
    private String engineApiKey;

    private final ForensicCaseService service;

    public ForensicCaseController(ForensicCaseService service) {
        this.service = service;
    }

    // ── CASES ───────────────────────────────────────

    @GetMapping("/cases")
    public ResponseEntity<?> listCases(
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String suspectIp,
            @RequestParam(required = false) String suspectMac,
            @RequestParam(required = false) String assignedTo) {

        if (status != null)
            return ResponseEntity.ok(service.getByStatus(status));

        if (suspectIp != null)
            return ResponseEntity.ok(service.getBySuspectIp(suspectIp));

        if (suspectMac != null)
            return ResponseEntity.ok(service.getBySuspectMac(suspectMac));

        if (assignedTo != null)
            return ResponseEntity.ok(service.getByAssignee(assignedTo));

        return ResponseEntity.ok(service.getAll());
    }

    @GetMapping("/cases/{id}")
    public ResponseEntity<?> getCase(@PathVariable Long id) {
        return service.getById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/cases/number/{caseNumber}")
    public ResponseEntity<?> getCaseByNumber(@PathVariable String caseNumber) {
        return service.getByNumber(caseNumber)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/cases")
    public ResponseEntity<?> createCase(@RequestBody ForensicCase fc,
                                        Authentication auth) {

        String username = (auth != null) ? auth.getName() : "system";
        return ResponseEntity.ok(service.create(fc, username));
    }

    /**
     * NEW: create a case directly from an alert — the "Investigate" quick
     * action on the Alerts tab. Body: { "title": "...", "priority": "HIGH" }
     * (both optional — title falls back to a generated one, priority to MEDIUM).
     */
    @PostMapping("/cases/from-alert/{alertId}")
    public ResponseEntity<?> createFromAlert(@PathVariable Long alertId,
                                             @RequestBody(required = false) Map<String, String> body,
                                             Authentication auth) {
        String username = (auth != null) ? auth.getName() : "system";
        String title    = body != null ? body.get("title")    : null;
        String priority = body != null ? body.get("priority") : null;
        return ResponseEntity.ok(service.createFromAlert(alertId, title, priority, username));
    }

    @PutMapping("/cases/{id}")
    public ResponseEntity<?> updateCase(@PathVariable Long id,
                                        @RequestBody ForensicCase patch,
                                        Authentication auth) {

        String username = (auth != null) ? auth.getName() : "system";
        return ResponseEntity.ok(service.update(id, patch, username));
    }

    /**
     * NEW: dedicated status transition. Body: { "status": "IN_PROGRESS" }
     * Kept separate from PUT /cases/{id} so the quick-action buttons in the
     * desktop Overview tab can fire a tiny PATCH instead of round-tripping
     * the whole case object back to the server.
     */
    @PatchMapping("/cases/{id}/status")
    public ResponseEntity<?> updateStatus(@PathVariable Long id,
                                          @RequestBody Map<String, String> body,
                                          Authentication auth) {
        String username  = (auth != null) ? auth.getName() : "system";
        String newStatus = body.get("status");
        if (newStatus == null || newStatus.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "status is required"));
        }
        return ResponseEntity.ok(service.updateStatus(id, newStatus, username));
    }

    /**
     * NEW: dedicated assign action. Body: { "analyst": "jdoe" }
     */
    @PatchMapping("/cases/{id}/assign")
    public ResponseEntity<?> assignCase(@PathVariable Long id,
                                        @RequestBody Map<String, String> body,
                                        Authentication auth) {
        String username = (auth != null) ? auth.getName() : "system";
        String analyst  = body.get("analyst");
        if (analyst == null || analyst.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "analyst is required"));
        }
        return ResponseEntity.ok(service.assign(id, analyst, username));
    }

    @DeleteMapping("/cases/{id}")
    public ResponseEntity<?> deleteCase(@PathVariable Long id) {
        service.delete(id);
        return ResponseEntity.ok(Map.of("message", "Case deleted"));
    }

    // ── CASE DETAIL (NEW — wires up the already-implemented service method) ──

    /**
     * GET /api/forensics/cases/{id}/detail
     * Single-call payload for the desktop CaseDetailPanel: case fields +
     * linkedAlerts (≤500) + timeline + notes. See ForensicCaseService.getDetail().
     */
    @GetMapping("/cases/{id}/detail")
    public ResponseEntity<?> getCaseDetail(@PathVariable Long id) {
        return service.getDetail(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    // ── NOTES (NEW) ───────────────────────────────────────────────────────────

    @GetMapping("/cases/{id}/notes")
    public ResponseEntity<?> getNotes(@PathVariable Long id) {
        return ResponseEntity.ok(service.getNotes(id));
    }

    /**
     * POST /api/forensics/cases/{id}/notes
     * Body: { "content": "..." }   (author comes from the JWT, not the body —
     * never trust the client to say who they are)
     */
    @PostMapping("/cases/{id}/notes")
    public ResponseEntity<?> addNote(@PathVariable Long id,
                                     @RequestBody CaseNote body,
                                     Authentication auth) {
        String username = (auth != null) ? auth.getName() : "system";
        return ResponseEntity.ok(service.addNote(id, body.getContent(), username));
    }

    @DeleteMapping("/cases/notes/{noteId}")
    public ResponseEntity<?> deleteNote(@PathVariable Long noteId) {
        service.deleteNote(noteId);
        return ResponseEntity.ok(Map.of("message", "Note deleted"));
    }

    // ── TIMELINE (NEW) ────────────────────────────────────────────────────────

    @GetMapping("/cases/{id}/timeline")
    public ResponseEntity<?> getTimeline(@PathVariable Long id) {
        return ResponseEntity.ok(service.getTimeline(id));
    }

    // ── PACKETS (unchanged) ──────────────────────────────────────────────────

    @GetMapping("/packets")
    public ResponseEntity<?> listPackets(
            @RequestParam(required = false) String ip,
            @RequestParam(required = false) String mac,
            @RequestParam(required = false) Long caseId) {

        if (ip != null)
            return ResponseEntity.ok(service.getPacketsByIp(ip));

        if (mac != null)
            return ResponseEntity.ok(service.getPacketsByMac(mac));

        if (caseId != null)
            return ResponseEntity.ok(service.getPacketsByCase(caseId));

        return ResponseEntity.ok(service.getRecentPackets());
    }

    @PostMapping("/packets")
    public ResponseEntity<?> ingestPacket(
            @RequestHeader(value = "X-Engine-Key", required = false) String key,
            @RequestBody PacketLog log) {

        if (key == null || !key.equals(engineApiKey)) {
            return ResponseEntity.status(403)
                    .body(Map.of("error", "Invalid engine key"));
        }

        return ResponseEntity.ok(service.savePacketLog(log));
    }

    @PostMapping("/cases/{caseId}/packets/{packetId}")
    public ResponseEntity<?> linkPacket(@PathVariable Long caseId,
                                        @PathVariable Long packetId) {

        PacketLog log = service.getPacketById(packetId)
                .orElseThrow(() -> new RuntimeException("Packet not found"));

        if (caseId.equals(log.getCaseId())) {
            return ResponseEntity.ok(Map.of("message", "Already linked"));
        }

        log.setCaseId(caseId);
        service.savePacketLog(log);

        return ResponseEntity.ok(Map.of("message", "Packet linked successfully"));
    }
    /**
     * GET /api/forensics/cases/alert-groups
     * Powers the "Create Cases from Alerts" screen — one row per source IP
     * with alert stats and whether a case already exists for it.
     */
    @GetMapping("/cases/alert-groups")
    public ResponseEntity<?> getAlertGroups() {
        return ResponseEntity.ok(service.getAlertGroupsForCaseCreation());
    }

    /**
     * POST /api/forensics/cases/from-ip/{ip}
     * Bulk case creation entry point. Idempotent by design — calling this
     * twice for the same IP returns the existing case both times rather
     * than erroring or duplicating.
     */
    @PostMapping("/cases/from-ip/{ip}")
    public ResponseEntity<?> createCaseFromIp(@PathVariable String ip, Authentication auth) {
        String username = (auth != null) ? auth.getName() : "system";
        return ResponseEntity.ok(service.createFromIpGroup(ip, username));
    }
}