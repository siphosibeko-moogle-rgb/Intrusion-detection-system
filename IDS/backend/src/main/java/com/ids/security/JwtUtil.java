package com.ids.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil {

    private static final Logger log = LoggerFactory.getLogger(JwtUtil.class);

    @Value("${ids.jwt.secret}")
    private String secret;

    @Value("${ids.jwt.expiration}")
    private long expirationMs;

    // Fail fast at startup: a missing/short HS256 secret would otherwise only
    // blow up on first login (jjwt requires >= 32 bytes) and is brute-forceable.
    @PostConstruct
    void validateSecret() {
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException(
                "JWT secret is not configured. Set IDS_JWT_SECRET to a random value of at least 32 bytes.");
        }
        if (secret.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalStateException(
                "JWT secret is too short for HS256 (" + secret.getBytes(StandardCharsets.UTF_8).length
                + " bytes). Set IDS_JWT_SECRET to a random value of at least 32 bytes.");
        }
    }

    private Key key() { return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)); }

    public String generate(String username, String role) {
        return Jwts.builder()
            .setSubject(username)
            .claim("role", role)
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + expirationMs))
            .signWith(key(), SignatureAlgorithm.HS256)
            .compact();
    }

    public String extractUsername(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public String extractRole(String token) {

        Claims claims =
                Jwts.parserBuilder()
                    .setSigningKey(key())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

        return claims.get("role", String.class);
    }

    public boolean validate(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key()).build().parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.warn("JWT rejected — expired at {}", e.getClaims().getExpiration());
            return false;
        } catch (JwtException e) {
            log.warn("JWT rejected — {}: {}", e.getClass().getSimpleName(), e.getMessage());
            return false;
        }
    }
}