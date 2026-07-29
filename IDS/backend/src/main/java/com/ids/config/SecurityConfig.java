package com.ids.config;

import com.ids.repository.UserRepository;
import com.ids.security.JwtFilter;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Two independent filter chains:
 *
 * 1. API chain (order 1) — everything the desktop client and engine use:
 *    /api/**, /ws/**, /actuator/**. Stateless, JWT via JwtFilter, CSRF off.
 *    Unchanged behavior from the pre-split config.
 *
 * 2. Web chain (order 2, catch-all) — the minimal browser UI (register,
 *    login, engine-key request/approval). Session + form login, CSRF on.
 *    Anything not explicitly listed is denied: the web surface is only
 *    /register, /login, /engines/**, /admin/**.
 */
@Configuration
@EnableWebSecurity
// Enables @PreAuthorize so destructive endpoints can be restricted to ADMIN.
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtFilter jwtFilter;

    public SecurityConfig(JwtFilter jwtFilter) {
        this.jwtFilter = jwtFilter;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /** Backs form login on the web chain. JwtFilter does not use this. */
    @Bean
    public UserDetailsService userDetailsService(UserRepository userRepo) {
        return username -> userRepo.findByUsername(username)
            .map(u -> org.springframework.security.core.userdetails.User
                .withUsername(u.getUsername())
                .password(u.getPassword())
                .roles(u.getRole() == null || u.getRole().isBlank()
                        ? "ANALYST" : u.getRole())
                .build())
            .orElseThrow(() -> new UsernameNotFoundException("Unknown user"));
    }

    @Bean
    @Order(1)
    public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {

        http
            .securityMatcher("/api/**", "/ws/**", "/actuator/**")

            .csrf(csrf -> csrf.disable())

            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // Without this, Spring Security's default entry point returns 403
            // for every unauthenticated/invalid-token request, which masks
            // the real cause and breaks any client logic that branches on 401.
            .exceptionHandling(ex -> ex.authenticationEntryPoint(
                (request, response, authException) ->
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                        "Invalid or expired token")))

            .authorizeHttpRequests(auth -> auth
                    // Public — no JWT required
                    // Only health/info are public; other actuator endpoints
                    // (env, heapdump, ...) leak secrets so they need a JWT.
                    // /api/my-whitelist removed from permitAll: it exposed
                    // read/write/delete of trusted devices unauthenticated.
                    .requestMatchers(
                        "/api/auth/login",
                        "/api/auth/register",
                        "/actuator/health",
                        "/actuator/info",
                        "/api/alerts/ingest",    // engine uses X-Engine-Key, validated in controller
                        "/api/engine/heartbeat", // same X-Engine-Key scheme as ingest
                        "/ws/**"
                    ).permitAll()

                    // Everything else requires a valid JWT
                    .anyRequest().authenticated()
            )

            .addFilterBefore(
                jwtFilter,
                UsernamePasswordAuthenticationFilter.class
            );

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain webFilterChain(HttpSecurity http) throws Exception {

        http
            // CSRF stays enabled (session-based forms). Thymeleaf adds the
            // token to every th:action form automatically.
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/register", "/login", "/error").permitAll()
                    .requestMatchers("/engines/**").authenticated()
                    .requestMatchers("/admin/**").hasRole("ADMIN")
                    .anyRequest().denyAll()
            )

            .formLogin(form -> form
                    .loginPage("/login")
                    .defaultSuccessUrl("/engines", true)
                    .permitAll())

            .logout(logout -> logout
                    .logoutUrl("/logout")
                    .logoutSuccessUrl("/login?logout"));

        return http.build();
    }
}
