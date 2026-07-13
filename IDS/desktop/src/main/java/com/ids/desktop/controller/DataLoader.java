package com.ids.desktop.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.ids.desktop.model.*;
import com.ids.desktop.service.BackendClient;
import javafx.application.Platform;

import java.util.List;
import java.util.function.Consumer;

/**
 * Owns all background data loading.
 * Never touches UI directly — all results delivered via Platform.runLater().
 */
public class DataLoader {

    @FunctionalInterface
    public interface WhitelistCallback {
        void accept(List<MyWhitelistItem> my,
                    List<FlaggedIpItem> flagged);
    }

    @FunctionalInterface
    public interface ThrowingRunnable {
        void run() throws Exception;
    }

    private final BackendClient backend;

    public DataLoader(BackendClient backend) {
        this.backend = backend;
    }

    public void loadAlerts(Consumer<List<AlertItem>> onAlerts,
                           Consumer<JsonNode> onStats,
                           Consumer<String> onError) {
        thread("ids-load-alerts", () -> {
            try {
                List<AlertItem> items = backend.fetchAlerts();
                JsonNode stats = backend.fetchStats();

                Platform.runLater(() -> {
                    onAlerts.accept(items);
                    onStats.accept(stats);
                });
            } catch (Exception e) {
                Platform.runLater(() -> onError.accept(e.getMessage()));
            }
        });
    }

    public void loadWhitelist(WhitelistCallback onLoaded,
                              Consumer<String> onError) {
        thread("ids-load-whitelist", () -> {
            try {
                List<MyWhitelistItem> myItems = backend.fetchMyWhitelist();
                List<FlaggedIpItem> flagged = backend.fetchFlaggedIps();

                Platform.runLater(() ->
                        onLoaded.accept(myItems, flagged));

            } catch (Exception e) {
                Platform.runLater(() -> onError.accept(e.getMessage()));
            }
        });
    }

    /**
     * Loads forensic cases.
     * BackendClient is responsible for mapping JSON into CaseItem objects.
     */
    public void loadCases(Consumer<List<CaseItem>> onCases,
                          Consumer<String> onError) {

        thread("ids-load-cases", () -> {
            try {
                List<CaseItem> items = backend.fetchCases();

                Platform.runLater(() -> onCases.accept(items));

            } catch (Exception e) {
                Platform.runLater(() -> onError.accept(e.getMessage()));
            }
        });
    }

    public void login(String user,
                      String pass,
                      Runnable onSuccess,
                      Consumer<String> onFailure) {

        thread("ids-login-thread", () -> {
            try {
                boolean ok = backend.login(user, pass);

                Platform.runLater(() -> {
                    if (ok) {
                        onSuccess.run();
                    } else {
                        onFailure.accept("Invalid credentials");
                    }
                });

            } catch (Exception e) {
                Platform.runLater(() -> onFailure.accept(e.getMessage()));
            }
        });
    }

    public void submit(String threadName,
                       ThrowingRunnable action,
                       Runnable onSuccess,
                       Consumer<String> onError) {

        thread(threadName, () -> {
            try {
                action.run();
                Platform.runLater(onSuccess);
            } catch (Exception e) {
                Platform.runLater(() -> onError.accept(e.getMessage()));
            }
        });
    }

    public void loadAlertSummaries(Consumer<List<AlertItem>> onAlerts,
                                   Consumer<JsonNode> onStats,
                                   Consumer<String> onError) {

        thread("ids-load-alert-summaries", () -> {
            try {
                List<AlertItem> items = backend.fetchAlertSummaries();
                JsonNode stats = backend.fetchStats();

                Platform.runLater(() -> {
                    onAlerts.accept(items);
                    onStats.accept(stats);
                });

            } catch (Exception e) {
                Platform.runLater(() -> onError.accept(e.getMessage()));
            }
        });
    }

    private void thread(String name, Runnable runnable) {
        Thread t = new Thread(runnable, name);
        t.setDaemon(true);
        t.start();
    }
}