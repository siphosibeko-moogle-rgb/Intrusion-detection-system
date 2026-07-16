package com.ids.controller;

import com.ids.model.User;
import com.ids.repository.UserRepository;
import com.ids.service.EngineKeyService;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * "My Engines" page: a user's own engine keys (prefix + status only —
 * raw keys are never re-displayed) and the request-new-key form.
 */
@Controller
@RequestMapping("/engines")
public class EnginePageController {

    private final EngineKeyService keyService;
    private final UserRepository   userRepo;

    public EnginePageController(EngineKeyService keyService, UserRepository userRepo) {
        this.keyService = keyService;
        this.userRepo   = userRepo;
    }

    @GetMapping
    public String myEngines(Authentication auth, Model model) {
        User user = currentUser(auth);
        model.addAttribute("username", user.getUsername());
        model.addAttribute("isAdmin", "ADMIN".equals(user.getRole()));
        model.addAttribute("keys", keyService.getViewsForOwner(user.getId()));
        return "engines";
    }

    @PostMapping("/request")
    public String requestKey(@RequestParam String name,
                             Authentication auth,
                             RedirectAttributes redirect) {
        if (name == null || name.isBlank()) {
            redirect.addFlashAttribute("error", "Please give the engine a name.");
            return "redirect:/engines";
        }
        keyService.request(currentUser(auth), name.trim());
        redirect.addFlashAttribute("message",
            "Key requested — an administrator has to approve it before it becomes active.");
        return "redirect:/engines";
    }

    private User currentUser(Authentication auth) {
        return userRepo.findByUsername(auth.getName())
            .orElseThrow(() -> new IllegalStateException("Authenticated user not found"));
    }
}
