package com.ids.config;

import com.ids.model.User;
import com.ids.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * One-time bootstrap for the first ADMIN account — without it nobody can
 * approve the first engine key. Runs only when NO admin exists yet and both
 * IDS_ADMIN_USERNAME / IDS_ADMIN_PASSWORD are set; a no-op on every boot
 * after that, so the env vars can (and should) be removed once the admin
 * has logged in.
 */
@Component
public class AdminBootstrap implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AdminBootstrap.class);

    private final UserRepository  userRepo;
    private final PasswordEncoder encoder;

    @Value("${ids.bootstrap.admin.username:}")
    private String username;

    @Value("${ids.bootstrap.admin.password:}")
    private String password;

    public AdminBootstrap(UserRepository userRepo, PasswordEncoder encoder) {
        this.userRepo = userRepo;
        this.encoder  = encoder;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (userRepo.existsByRole("ADMIN"))
            return;
        if (username == null || username.isBlank()
                || password == null || password.isBlank()) {
            log.warn("No ADMIN account exists and ids.bootstrap.admin.username/"
                   + "password are not set — engine-key approvals are impossible "
                   + "until one is configured.");
            return;
        }
        userRepo.findByUsername(username).ifPresentOrElse(
            existing -> {
                existing.setRole("ADMIN");
                userRepo.save(existing);
                log.info("Bootstrap: promoted existing user '{}' to ADMIN", username);
            },
            () -> {
                userRepo.save(new User(username, encoder.encode(password), "ADMIN"));
                log.info("Bootstrap: created initial ADMIN account '{}'", username);
            });
    }
}
