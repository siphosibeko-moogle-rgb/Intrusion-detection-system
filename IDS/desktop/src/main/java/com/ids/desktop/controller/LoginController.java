package com.ids.desktop.controller;

import com.ids.desktop.service.BackendClient;

import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;

import java.util.function.BiConsumer;

/**
 * Controller for the standalone login window (login.fxml) shown before the
 * main window. Authenticates via the same BackendClient + DataLoader path
 * MainController used to own, then hands the authenticated instances to
 * IDSDesktopApp through the onLoginSuccess callback so the session is
 * established exactly once.
 */
public class LoginController {

    private static final String DEFAULT_BACKEND_URL = "http://localhost:8080";

    @FXML private TextField     tfBackendUrl;
    @FXML private TextField     tfUsername;
    @FXML private PasswordField pfPassword;
    @FXML private Label         lblLoginStatus;

    /** Set by IDSDesktopApp; receives the already-authenticated instances. */
    private BiConsumer<BackendClient, DataLoader> onLoginSuccess;

    public void setOnLoginSuccess(BiConsumer<BackendClient, DataLoader> onLoginSuccess) {
        this.onLoginSuccess = onLoginSuccess;
    }

    @FXML
    private void onLogin() {
        String user = tfUsername.getText().trim();
        String pass = pfPassword.getText();

        if (user.isEmpty() || pass.isEmpty()) {
            lblLoginStatus.setText("Username and password required");
            return;
        }
        lblLoginStatus.setText("Connecting...");

        BackendClient backend    = new BackendClient(backendUrl());
        DataLoader    dataLoader = new DataLoader(backend);

        dataLoader.login(user, pass,
                () -> onLoginSuccess.accept(backend, dataLoader),
                msg -> lblLoginStatus.setText("Connection failed: " + msg));
    }

    private String backendUrl() {
        String url = tfBackendUrl != null ? tfBackendUrl.getText() : null;
        if (url == null || url.isBlank()) return DEFAULT_BACKEND_URL;
        url = url.trim();
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
