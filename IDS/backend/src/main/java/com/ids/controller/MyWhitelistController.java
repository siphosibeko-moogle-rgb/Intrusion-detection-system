package com.ids.controller;

import com.ids.entity.MyWhitelistEntry;
import com.ids.service.MyWhitelistService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import java.util.List; import java.util.Map;

@RestController
@RequestMapping("/api/my-whitelist")
public class MyWhitelistController {

    private final MyWhitelistService svc;
    public MyWhitelistController(MyWhitelistService svc) { this.svc = svc; }

    @GetMapping
    public List<MyWhitelistEntry> getAll() { return svc.getAll(); }

    // Whitelisting a device disables all detection for it. ANALYST is
    // intentionally granted parity with ADMIN here (role-consolidation
    // decision) — this may later be narrowed back to ADMIN-only.
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    @PostMapping
    public MyWhitelistEntry add(@RequestBody Map<String,String> body) {
        return svc.add(body.get("ip"), body.get("mac"), body.get("label"));
    }

    // Removing an entry un-trusts a real device. ANALYST is intentionally
    // granted parity with ADMIN here (role-consolidation decision) — this
    // may later be narrowed back to ADMIN-only.
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    @DeleteMapping("/{id}")
    public void delete(@PathVariable Long id) { svc.delete(id); }
}