package com.ids.config;

import com.ids.security.JwtFilter;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
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
}