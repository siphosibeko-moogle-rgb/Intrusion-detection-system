package com.ids.controller;

import com.ids.model.EngineKey;
import com.ids.service.EngineKeyService;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Heartbeat so a healthy sensor on a quiet network still reports as ONLINE —
 * liveness otherwise only advances when an alert is ingested. Body fields
 * are accepted but ignored; only auth (and its side-effect liveness touch)
 * matters here. No JWT required — same X-Engine-Key scheme as ingest.
 */
@RestController
@RequestMapping("/api/engine")
public class EngineHeartbeatController {

    private final EngineKeyService engineKeyService;

    public EngineHeartbeatController(EngineKeyService engineKeyService) {
        this.engineKeyService = engineKeyService;
    }

    @PostMapping("/heartbeat")
    public ResponseEntity<?> heartbeat(@RequestHeader(value = "X-Engine-Key", required = false) String key,
                                       @RequestBody(required = false) Map<String, Object> body) {
        EngineKey engineKey = engineKeyService.authenticate(key).orElse(null);
        if (engineKey == null)
            return ResponseEntity.status(401).body(Map.of("error", "Invalid engine key"));

        return ResponseEntity.ok(Map.of("status", "ok", "engine", engineKey.getKeyPrefix()));
    }
}
