package com.ids.controller;

import com.ids.model.User;
import com.ids.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Web registration + login pages. Registration always creates an ANALYST
 * account — role is never taken from the request. Web self-registration
 * grants ANALYST (not ADMIN) because a web account has no web-UI access of
 * its own anyway; ANALYST is what lets the account be used from the desktop
 * client. The email is stored in the existing users.username column
 * (desktop JWT login is unaffected).
 */
@Controller
public class WebAuthController {

    private final UserRepository  userRepo;
    private final PasswordEncoder encoder;

    public WebAuthController(UserRepository userRepo, PasswordEncoder encoder) {
        this.userRepo = userRepo;
        this.encoder  = encoder;
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/register")
    public String registerForm() {
        return "register";
    }

    @PostMapping("/register")
    public String register(@RequestParam String email,
                           @RequestParam String password,
                           Model model) {
        String error = null;
        if (email == null || email.isBlank() || !email.contains("@"))
            error = "A valid email address is required.";
        else if (password == null || password.length() < 8)
            error = "Password must be at least 8 characters.";
        else if (userRepo.findByUsername(email.trim()).isPresent())
            error = "An account with that email already exists.";

        if (error != null) {
            model.addAttribute("error", error);
            model.addAttribute("email", email);
            return "register";
        }

        userRepo.save(new User(email.trim(), encoder.encode(password), "ANALYST"));
        return "redirect:/login?registered";
    }
}
