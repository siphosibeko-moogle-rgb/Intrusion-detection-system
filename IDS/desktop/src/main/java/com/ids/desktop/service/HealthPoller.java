package com.ids.desktop.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import javafx.application.Platform;

import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * HealthPoller — single shared poller for GET /api/dashboard/health.
 *
 * WHY THIS EXISTS
 * ----------------
 * Previously DashboardPanel ran its own 5s poll of /api/dashboard/health as
 * part of a combined summary+health refresh loop. The header mini-health
 * widget needs the same data. Two independent pollers hitting the same
 * endpoint on the same cadence is wasted backend load for zero benefit, and
 * worse, they could disagree for a moment — the header dot and the
 * Dashboard tab's health widget could show different colors for the same
 * real-world fact. One poller, many listeners, one truth.
 *
 * THREADING
 * ---------
 * HTTP happens on a single daemon scheduler thread ("ids-health-poller").
 * Every listener is invoked via Platform.runLater().
 *
 * LIFECYCLE
 * ---------
 * MainController owns one instance, starts it after login, stops it in
 * shutdown().
 */
public class HealthPoller {

    private final ObjectMapper mapper = new ObjectMapper();
    private final CopyOnWriteArrayList<Consumer<JsonNode>> listeners = new CopyOnWriteArrayList<>();
    private BackendClient backend;
    private ScheduledExecutorService scheduler;

    public HealthPoller(BackendClient backend) {
        this.backend = backend;
    }

    public void setBackend(BackendClient backend) {
        this.backend = backend;
    }

    /** Registers a listener. Safe to call before or after start(). */
    public void addListener(Consumer<JsonNode> listener) {
        listeners.add(listener);
    }

    /** Starts the 5-second poll loop. Safe to call more than once (restarts). */
    public void start() {
        stop(); // guard against double-start leaking a thread
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "ids-health-poller");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleWithFixedDelay(this::poll, 0, 5, TimeUnit.SECONDS);
    }

    /** Stops polling. Call from MainController.shutdown(). */
    public void stop() {
        if (scheduler != null) {
            scheduler.shutdownNow();
            scheduler = null;
        }
    }

    private void poll() {
        if (backend == null || !backend.isLoggedIn()) return;
        try {
            JsonNode health = mapper.readTree(backend.getRaw("/api/dashboard/health"));
            Platform.runLater(() -> {
                for (Consumer<JsonNode> l : listeners) {
                    try {
                        l.accept(health);
                    } catch (Exception ignored) {
                        // One bad listener must not stop the others from updating.
                    }
                }
            });
        } catch (Exception ignored) {
            // Network hiccup — next poll in 5s will retry.
        }
    }
}