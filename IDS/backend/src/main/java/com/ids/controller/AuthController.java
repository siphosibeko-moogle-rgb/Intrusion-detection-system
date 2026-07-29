package com.ids.controller;

import com.ids.model.User;
import com.ids.repository.UserRepository;
import com.ids.security.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository  userRepo;
    private final JwtUtil         jwtUtil;
    private final PasswordEncoder encoder;

    public AuthController(UserRepository userRepo,
                          JwtUtil jwtUtil,
                          PasswordEncoder encoder) {
        this.userRepo = userRepo;
        this.jwtUtil  = jwtUtil;
        this.encoder  = encoder;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String password = body.get("password");

        Optional<User> userOpt = userRepo.findByUsername(username);
        if (userOpt.isEmpty() || !encoder.matches(password, userOpt.get().getPassword()))
            return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));

        User user = userOpt.get();
        return ResponseEntity.ok(Map.of(
            "token",    jwtUtil.generate(username, user.getRole()),
            "username", username,
            "role",     user.getRole()
        ));
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String password = body.get("password");
        String role     = body.getOrDefault("role", "ANALYST");

        if (userRepo.findByUsername(username).isPresent())
            return ResponseEntity.badRequest().body(Map.of("error", "Username already exists"));

        userRepo.save(new User(username, encoder.encode(password), role));
        return ResponseEntity.ok(Map.of("message", "User created", "username", username));
    }

    @GetMapping("/me")
    public ResponseEntity<?> me(Authentication auth) {
        if (auth == null) return ResponseEntity.status(401).build();
        return userRepo.findByUsername(auth.getName())
            .map(u -> ResponseEntity.ok(Map.of(
                "username", u.getUsername(),
                "role",     u.getRole())))
            .orElse(ResponseEntity.notFound().build());
    }
}