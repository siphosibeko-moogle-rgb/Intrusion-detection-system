package com.ids.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ids.dto.ThreatEventDTO;
import com.ids.service.ThreatEventService;

@RestController
@RequestMapping("/api/threats")
public class ThreatEventController {

    private final ThreatEventService service;

    public ThreatEventController(ThreatEventService service) {
        this.service = service;
    }

    @PostMapping
    public ResponseEntity<String> receiveThreat(@RequestBody ThreatEventDTO dto) {
        service.saveEvent(dto);
        return ResponseEntity.ok("Threat stored successfully");
    }
}