package com.ids.mobile.ui;

import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.ids.mobile.R;
import com.ids.mobile.api.ApiClient;
import com.ids.mobile.api.Session;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class LoginActivity extends AppCompatActivity {

    private EditText etUrl, etUser, etPass;
    private Button btnLogin;
    private ProgressBar progress;
    private TextView tvError;

    // Single-use worker for the login call. Login is not a poll, so it does not
    // need Poller; it needs one off-main-thread execution and a clean shutdown.
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        etUrl    = findViewById(R.id.etUrl);
        etUser   = findViewById(R.id.etUsername);
        etPass   = findViewById(R.id.etPassword);
        btnLogin = findViewById(R.id.btnLogin);
        progress = findViewById(R.id.progress);
        tvError  = findViewById(R.id.tvError);

        etUrl.setText(Session.loadBaseUrl(this));
        btnLogin.setOnClickListener(v -> attemptLogin());
    }

    private void attemptLogin() {
        final String url  = etUrl.getText().toString().trim();
        final String user = etUser.getText().toString().trim();
        final String pass = etPass.getText().toString();

        if (TextUtils.isEmpty(url) || TextUtils.isEmpty(user) || TextUtils.isEmpty(pass)) {
            showError(getString(R.string.error_fields_required));
            return;
        }
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            showError(getString(R.string.error_bad_url));
            return;
        }

        setBusy(true);
        Session.saveBaseUrl(this, url);
        Session.init(url);

        worker.execute(() -> {
            boolean ok;
            String failure = null;
            try {
                ApiClient client = Session.client();
                ok = client != null && client.login(user, pass);
                if (!ok) failure = getString(R.string.error_bad_credentials);
            } catch (Exception e) {
                ok = false;
                // Distinguish "server unreachable" from "wrong password": on a
                // LAN app the former is far more common, and telling the user
                // their password is wrong when the backend is simply down sends
                // them debugging the wrong thing entirely.
                failure = getString(R.string.error_unreachable) + "\n" + e.getMessage();
            }

            final boolean success = ok;
            final String message = failure;
            main.post(() -> {
                setBusy(false);
                if (success) {
                    startActivity(new Intent(LoginActivity.this, MainActivity.class));
                    finish();
                } else {
                    showError(message);
                }
            });
        });
    }

    private void setBusy(boolean busy) {
        progress.setVisibility(busy ? View.VISIBLE : View.GONE);
        btnLogin.setEnabled(!busy);
        if (busy) tvError.setVisibility(View.GONE);
    }

    private void showError(String msg) {
        tvError.setText(msg);
        tvError.setVisibility(View.VISIBLE);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        worker.shutdownNow();
    }
}
