package com.ids.config;

import com.ids.security.JwtFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
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

            .authorizeHttpRequests(auth -> auth

                // Public — no JWT needed
                .requestMatchers(
                    "/api/auth/login",
                    "/api/auth/register",
                    "/actuator/**"
                ).permitAll()

                // Engine ingest — uses X-Engine-Key header, not JWT.
                // The controller validates the key itself.
                // WHY permit here: the engine process has no user session —
                // it authenticates via a shared secret, not a JWT token.
                .requestMatchers(
                	    "/api/auth/login",
                	    "/api/auth/register", 
                	    "/actuator/**",
                	    "/api/alerts/ingest",
                	    "/api/my-whitelist"      // ← add this
                	).permitAll()

                // WebSocket handshake endpoint — must be permit-all
                // because the WS upgrade happens before auth is established.
                .requestMatchers("/ws/**").permitAll()

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