package com.ids.controller;

import com.ids.entity.OrgWhitelistEntry;
import com.ids.service.OrgWhitelistService;
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
    @PatchMapping("/{id}/approve")
    public void approve(@PathVariable Long id) { svc.approve(id); }
    @PatchMapping("/approve-all")
    public void approveAll() { svc.approveAll(); }
    @DeleteMapping("/{id}")
    public void delete(@PathVariable Long id) { svc.delete(id); }
    
 // In OrgWhitelistController.java — add this method
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