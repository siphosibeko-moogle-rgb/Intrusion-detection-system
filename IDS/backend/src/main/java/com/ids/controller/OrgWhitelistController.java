package com.ids.controller;

import com.ids.entity.OrgWhitelistEntry;
import com.ids.service.OrgWhitelistService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/org-whitelist")
public class OrgWhitelistController {
    private final OrgWhitelistService svc;
    public OrgWhitelistController(OrgWhitelistService svc) { this.svc = svc; }
    @GetMapping
    public List<OrgWhitelistEntry> getAll() { return svc.getAll(); }
    // Approving an org whitelists its IP ranges past the detectors. ANALYST
    // is intentionally granted parity with ADMIN here (role-consolidation
    // decision) — this may later be narrowed back to ADMIN-only.
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    @PatchMapping("/{id}/approve")
    public void approve(@PathVariable Long id) { svc.approve(id); }
    // Same rationale as approve() above: ANALYST parity is intentional and
    // may later be narrowed back to ADMIN-only.
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    @PatchMapping("/approve-all")
    public void approveAll() { svc.approveAll(); }
    // Same rationale as approve() above: ANALYST parity is intentional and
    // may later be narrowed back to ADMIN-only.
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    @DeleteMapping("/{id}")
    public void delete(@PathVariable Long id) { svc.delete(id); }

    // Intentionally NOT admin-only: the engine (non-admin account) posts
    // discovered orgs here; entries stay unapproved until an admin approves.
    @PostMapping("/discover")
    public void discover(@RequestBody Map<String, String> body) {
        svc.recordOrUpdate(
            body.get("ip"),
            body.get("orgName"),
            body.get("asn"),
            body.get("country")
        );
    }
}