package com.ids.mobile.api;

import java.io.IOException;

/**
 * Thrown when the backend rejects our JWT with 401.
 *
 * DESIGN NOTE: the desktop client silently re-logs-in with cached credentials
 * on a 401. This app deliberately does NOT do that in v1 — it holds no password
 * after login, so there is nothing to retry with. Caching a password on a phone
 * means Keystore, biometric gating and a real threat model; that is a v2
 * decision, not something to bolt on quietly. Here a 401 simply bounces the
 * user back to the login screen, which is honest and cheap.
 */
public class AuthExpiredException extends IOException {
    public AuthExpiredException() {
        super("Session expired - please log in again");
    }
}
