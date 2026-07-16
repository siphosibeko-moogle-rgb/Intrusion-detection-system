package com.ids.controller;

import com.ids.dto.EngineKeyView;
import com.ids.enums.EngineKeyStatus;
import com.ids.repository.UserRepository;
import com.ids.service.EngineKeyService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Read-only fleet status for admins: summary counts plus every key with
 * liveness and alert count. No actions here — approve/reject/revoke live
 * on /admin/approvals. Guarded by the web chain's /admin/** hasRole(ADMIN).
 */
@Controller
@RequestMapping("/admin/agents")
public class AdminAgentsController {

    private final EngineKeyService keyService;
    private final UserRepository   userRepo;

    public AdminAgentsController(EngineKeyService keyService, UserRepository userRepo) {
        this.keyService = keyService;
        this.userRepo   = userRepo;
    }

    @GetMapping
    public String agents(Model model) {
        List<EngineKeyView> rows = keyService.getAllViews();

        Map<EngineKeyStatus, Long> byStatus = new EnumMap<>(EngineKeyStatus.class);
        Map<String, Long> activeLiveness = new HashMap<>();
        for (EngineKeyView r : rows) {
            byStatus.merge(r.getStatus(), 1L, Long::sum);
            if (r.getStatus() == EngineKeyStatus.ACTIVE)
                activeLiveness.merge(r.getLiveness(), 1L, Long::sum);
        }

        model.addAttribute("totalUsers",   userRepo.count());
        model.addAttribute("totalKeys",    rows.size());
        model.addAttribute("pendingCount", byStatus.getOrDefault(EngineKeyStatus.PENDING, 0L));
        model.addAttribute("activeCount",  byStatus.getOrDefault(EngineKeyStatus.ACTIVE,  0L));
        model.addAttribute("revokedCount", byStatus.getOrDefault(EngineKeyStatus.REVOKED, 0L));
        model.addAttribute("onlineCount",  activeLiveness.getOrDefault("ONLINE",  0L));
        model.addAttribute("staleCount",   activeLiveness.getOrDefault("STALE",   0L));
        model.addAttribute("offlineCount", activeLiveness.getOrDefault("OFFLINE", 0L));
        model.addAttribute("rows", rows);
        return "admin-agents";
    }
}
