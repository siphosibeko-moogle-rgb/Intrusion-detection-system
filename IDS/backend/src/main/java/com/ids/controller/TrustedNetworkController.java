package com.ids.controller;

import com.ids.entity.TrustedNetworkEntry;
import com.ids.service.TrustedNetworkService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/trusted-networks")
public class TrustedNetworkController {

    private final TrustedNetworkService svc;
    public TrustedNetworkController(TrustedNetworkService svc) { this.svc = svc; }

    @GetMapping
    public List<TrustedNetworkEntry> getAll() { return svc.getAll(); }

    @PostMapping
    public TrustedNetworkEntry add(@RequestBody Map<String, Object> body) {
        return svc.add(
            (String) body.get("cidr"),
            (String) body.get("provider"),
            (String) body.get("category"),
            (Boolean) body.get("enabled"),
            (Boolean) body.get("suppressBeaconing"));
    }

    @PatchMapping("/{id}")
    public TrustedNetworkEntry update(@PathVariable Long id,
                                      @RequestBody Map<String, Object> body) {
        return svc.update(id, body);
    }

    @DeleteMapping("/{id}")
    public void delete(@PathVariable Long id) { svc.delete(id); }

    // Validation failures (malformed CIDR, blank provider, duplicate range)
    // come back as 400 with the reason, not a generic 500.
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> badRequest(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
    }
}
