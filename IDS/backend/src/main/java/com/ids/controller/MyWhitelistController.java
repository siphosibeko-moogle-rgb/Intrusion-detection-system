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

    // ADMIN only: whitelisting a device disables all detection for it.
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping
    public MyWhitelistEntry add(@RequestBody Map<String,String> body) {
        return svc.add(body.get("ip"), body.get("mac"), body.get("label"));
    }

    // ADMIN only: removing an entry un-trusts a real device.
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{id}")
    public void delete(@PathVariable Long id) { svc.delete(id); }
}