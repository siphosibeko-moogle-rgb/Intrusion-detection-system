package com.ids.mobile.api;

import android.content.Context;
import android.content.SharedPreferences;

import com.ids.mobile.BuildConfig;

/**
 * Session — process-wide holder for the single ApiClient instance, plus
 * persistence of the backend URL only.
 *
 * WHAT IS PERSISTED: the base URL (a convenience, not a secret).
 * WHAT IS NOT PERSISTED: the username, the password, or the JWT.
 *
 * The token lives in memory inside ApiClient and dies with the process. That
 * means re-login after the app is killed. For a read-only glance client that is
 * the right trade: no token at rest means a lost or seized phone leaks nothing.
 */
public final class Session {

    private static final String PREFS = "ids_mobile_prefs";
    private static final String KEY_BASE_URL = "base_url";

    private static volatile ApiClient client;

    private Session() { }

    public static synchronized void init(String baseUrl) {
        client = new ApiClient(baseUrl);
    }

    /** May be null if the process was restarted after being killed in the background. */
    public static ApiClient client() {
        return client;
    }

    public static boolean isAuthenticated() {
        return client != null && client.isLoggedIn();
    }

    public static synchronized void clear() {
        if (client != null) client.logout();
        client = null;
    }

    public static String loadBaseUrl(Context ctx) {
        SharedPreferences p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        return p.getString(KEY_BASE_URL, BuildConfig.DEFAULT_BASE_URL);
    }

    public static void saveBaseUrl(Context ctx, String url) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
           .edit().putString(KEY_BASE_URL, url).apply();
    }
}
