package com.ids.controller;

import com.ids.entity.TriageVerdictEntity;
import com.ids.repository.TriageVerdictRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Read-only. Secured like every other dashboard endpoint: /api/** requires a
 * JWT by default (SecurityConfig) — no new auth wiring needed. Live verdicts
 * are pushed on /topic/triage as they're produced; these endpoints are for
 * backfill/refresh only.
 */
@RestController
@RequestMapping("/api/triage")
public class TriageController {

    private final TriageVerdictRepository repo;

    public TriageController(TriageVerdictRepository repo) {
        this.repo = repo;
    }

    @GetMapping("/{sourceIp}/{threatType}")
    public ResponseEntity<?> get(@PathVariable String sourceIp, @PathVariable String threatType) {
        return repo.findBySourceIpAndThreatType(sourceIp, threatType)
            .<ResponseEntity<?>>map(ResponseEntity::ok)
            .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/recent")
    public ResponseEntity<?> recent(@RequestParam(defaultValue = "50") int limit) {
        int capped = Math.max(1, Math.min(limit, 500));
        List<TriageVerdictEntity> verdicts = repo.findByOrderByAnalysedAtDesc(PageRequest.of(0, capped));
        return ResponseEntity.ok(verdicts);
    }
}
