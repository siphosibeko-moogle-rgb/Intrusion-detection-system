package com.ids.controller;

import com.ids.enums.EngineKeyStatus;
import com.ids.model.User;
import com.ids.repository.UserRepository;
import com.ids.service.EngineKeyService;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.UUID;

/**
 * Admin approvals page. Approving generates the key and flashes the RAW
 * key into the next (and only the next) page render — it is never stored,
 * logged, or shown again after that.
 */
@Controller
@RequestMapping("/admin/approvals")
public class AdminApprovalController {

    private final EngineKeyService keyService;
    private final UserRepository   userRepo;

    public AdminApprovalController(EngineKeyService keyService, UserRepository userRepo) {
        this.keyService = keyService;
        this.userRepo   = userRepo;
    }

    @GetMapping
    public String approvals(Model model) {
        model.addAttribute("pending", keyService.getByStatus(EngineKeyStatus.PENDING));
        model.addAttribute("active",  keyService.getByStatus(EngineKeyStatus.ACTIVE));
        return "admin-approvals";
    }

    @PostMapping("/{id}/approve")
    public String approve(@PathVariable UUID id,
                          Authentication auth,
                          RedirectAttributes redirect) {
        User admin = userRepo.findByUsername(auth.getName())
            .orElseThrow(() -> new IllegalStateException("Authenticated admin not found"));
        try {
            String rawKey = keyService.approve(id, admin);
            redirect.addFlashAttribute("issuedKey", rawKey);
        } catch (IllegalArgumentException | IllegalStateException e) {
            redirect.addFlashAttribute("error", e.getMessage());
        }
        return "redirect:/admin/approvals";
    }

    @PostMapping("/{id}/reject")
    public String reject(@PathVariable UUID id, RedirectAttributes redirect) {
        return revoke(id, redirect);
    }

    @PostMapping("/{id}/revoke")
    public String revoke(@PathVariable UUID id, RedirectAttributes redirect) {
        try {
            keyService.revoke(id);
        } catch (IllegalArgumentException e) {
            redirect.addFlashAttribute("error", e.getMessage());
        }
        return "redirect:/admin/approvals";
    }
}
