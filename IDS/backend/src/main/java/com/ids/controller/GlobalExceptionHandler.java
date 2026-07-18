package com.ids.controller;

import java.util.Map;
import java.util.NoSuchElementException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * One place for uncaught controller exceptions, so every REST endpoint
 * returns the same {"error": ...} JSON shape instead of the whitelabel
 * error page.
 *
 * Scoped to @RestController classes only — the Thymeleaf page controllers
 * (login/register/engines) must keep Spring's HTML error handling.
 *
 * A controller's own @ExceptionHandler (e.g. TrustedNetworkController's
 * IllegalArgumentException handler) still takes precedence over these.
 */
@RestControllerAdvice(annotations = RestController.class)
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<?> badRequest(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("error", e.getMessage() != null
                ? e.getMessage() : "Invalid request"));
    }

    @ExceptionHandler(NoSuchElementException.class)
    public ResponseEntity<?> notFound(NoSuchElementException e) {
        return ResponseEntity.status(404).body(Map.of("error", e.getMessage() != null
                ? e.getMessage() : "Not found"));
    }

    /**
     * Method-security failures (@PreAuthorize) must stay 403, not fall into
     * the generic 500 handler below.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<?> forbidden(AccessDeniedException e) {
        return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> internal(Exception e) {
        // Full detail to the log only — exception messages can carry
        // internals (SQL, file paths) that must not reach the client.
        log.error("Unhandled exception in REST controller", e);
        return ResponseEntity.status(500).body(Map.of("error", "Internal server error"));
    }
}
