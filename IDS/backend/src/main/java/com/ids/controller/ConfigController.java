package com.ids.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Properties;

/**
 * Whole-file editor endpoints for the engine's ids-whitelist.properties.
 *
 * The file is transported as raw text inside {"content": ...} so comments and
 * blank lines round-trip unchanged. PUT validates that the text parses as a
 * java.util.Properties file before overwriting anything, and requires
 * ROLE_ADMIN (JwtFilter grants ROLE_<role> from the token).
 *
 * The path is configurable via ids.whitelist.path / IDS_WHITELIST_PATH; the
 * default points at the engine's source copy for dev runs. The engine bakes
 * this file into its jar, so a running engine picks up changes on its next
 * rebuild/restart.
 */
@RestController
@RequestMapping("/api/config")
public class ConfigController {

    @Value("${ids.whitelist.path:../engine/src/main/resources/ids-whitelist.properties}")
    private String whitelistPath;

    @GetMapping("/whitelist-properties")
    public ResponseEntity<?> getWhitelistProperties() {
        Path path = Path.of(whitelistPath);
        if (!Files.isRegularFile(path)) {
            return ResponseEntity.status(404).body(Map.of(
                "error", "ids-whitelist.properties not found at " + path.toAbsolutePath()));
        }
        try {
            return ResponseEntity.ok(Map.of("content", Files.readString(path)));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
    }

    @PutMapping("/whitelist-properties")
    public ResponseEntity<?> putWhitelistProperties(@RequestBody Map<String, String> body,
                                                    Authentication auth) {
        boolean isAdmin = auth != null && auth.getAuthorities().stream()
            .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
        if (!isAdmin) {
            return ResponseEntity.status(403).body(Map.of("error", "ADMIN role required"));
        }

        String content = body.get("content");
        if (content == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing 'content'"));
        }
        try {
            new Properties().load(new StringReader(content));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Not a valid properties file: " + e.getMessage()));
        }

        try {
            Files.writeString(Path.of(whitelistPath), content);
            return ResponseEntity.ok(Map.of("status", "saved"));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
    }
}
