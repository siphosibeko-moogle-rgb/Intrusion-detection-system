package com.ids.desktop;

import com.ids.desktop.controller.MainController;
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
 * Features:
 *  - 4-tab interface: Alerts | Live Feed | Top Attackers | Settings
 *  - Wireshark-style alert table with 5 filter bars
 *  - Real-time WebSocket live feed
 *  - Colour-coded severity rows (CRITICAL=red, HIGH=orange, MEDIUM=yellow)
 *  - Source IP highlighted in cyan, MAC in purple on every row
 *  - Stat cards: Total / Critical / High / Medium
 *  - Auto-refresh every 30 seconds
 *  - JWT login from Settings tab
 *
 */
public class IDSDesktopApp extends Application {

    private MainController controller;

    @Override
    public void start(Stage stage) throws Exception {
        FXMLLoader loader = new FXMLLoader(
            getClass().getResource("/com/ids/desktop/main.fxml"));
        Parent root = loader.load();
        controller  = loader.getController();

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

        stage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}