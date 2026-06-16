package com.ids.controller;

import com.ids.model.ForensicCase;
import com.ids.model.PacketLog;
import com.ids.service.ForensicCaseService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Value;

import java.util.Map;

@RestController
@RequestMapping("/api/forensics")
public class ForensicCaseController {

    @Value("${ids.engine.apikey}")
    private String engineApiKey;

    private final ForensicCaseService service;

    public ForensicCaseController(ForensicCaseService service) {
        this.service = service;
    }

    // ── CASES ─────────────────────────────────────

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

    @PutMapping("/cases/{id}")
    public ResponseEntity<?> updateCase(@PathVariable Long id,
                                        @RequestBody ForensicCase patch,
                                        Authentication auth) {

        String username = (auth != null) ? auth.getName() : "system";
        return ResponseEntity.ok(service.update(id, patch, username));
    }

    @DeleteMapping("/cases/{id}")
    public ResponseEntity<?> deleteCase(@PathVariable Long id) {
        service.delete(id);
        return ResponseEntity.ok(Map.of("message", "Case deleted"));
    }

    // ── PACKETS ───────────────────────────────────

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

    // ── FIXED PACKET LINKING ─────────────────────

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
}