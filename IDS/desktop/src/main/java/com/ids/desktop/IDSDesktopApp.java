package com.ids.desktop;

import com.ids.desktop.controller.DataLoader;
import com.ids.desktop.controller.LoginController;
import com.ids.desktop.controller.MainController;
import com.ids.desktop.service.BackendClient;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

/**
 * IDS Desktop Monitor — JavaFX Application
 *
 * A native desktop application that connects to the IDS Spring Boot backend
 * and displays live alerts, statistics, and attacker data.
 *
 * Startup flow: a standalone login window is shown first (login.fxml /
 * LoginController). Only after a successful login is main.fxml loaded; the
 * already-authenticated BackendClient + DataLoader are handed to
 * MainController.startWithSession() so there is exactly one login and one
 * post-login wiring path. Closing the login window without logging in exits
 * the app cleanly.
 */
public class IDSDesktopApp extends Application {

    private MainController controller;

    @Override
    public void start(Stage loginStage) throws Exception {
        FXMLLoader loader = new FXMLLoader(
            getClass().getResource("/com/ids/desktop/login.fxml"));
        Parent root = loader.load();
        LoginController login = loader.getController();

        login.setOnLoginSuccess((backend, dataLoader) ->
            showMainWindow(loginStage, backend, dataLoader));

        loginStage.setTitle("IDS Monitor — Login");
        loginStage.setScene(new Scene(root));
        loginStage.setResizable(false);

        // Closing the login window without logging in exits the app.
        // hide() in showMainWindow() does NOT fire this handler.
        loginStage.setOnCloseRequest(e -> {
            Platform.exit();
            System.exit(0);
        });

        loginStage.show();
    }

    private void showMainWindow(Stage loginStage, BackendClient backend, DataLoader dataLoader) {
        try {
            FXMLLoader loader = new FXMLLoader(
                getClass().getResource("/com/ids/desktop/main.fxml"));
            Parent root = loader.load();
            controller  = loader.getController();
            controller.startWithSession(backend, dataLoader);

            Stage stage = new Stage();
            Scene scene = new Scene(root, 1400, 820);
            stage.setTitle("IDS Monitor v2.0 — Network Intrusion Detection");
            stage.setScene(scene);
            stage.setMinWidth(1000);
            stage.setMinHeight(600);

            stage.setOnCloseRequest(e -> {
                if (controller != null) controller.shutdown();
                Platform.exit();
                System.exit(0);
            });

            loginStage.hide();
            stage.show();
        } catch (Exception e) {
            System.err.println("[Desktop] Failed to open main window: " + e.getMessage());
            e.printStackTrace();
            Platform.exit();
            System.exit(1);
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}
