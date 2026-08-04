package com.ids.mobile.ui;

import android.content.Intent;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.Fragment;

import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.ids.mobile.R;
import com.ids.mobile.api.Session;

/**
 * Host activity: bottom nav swapping two read-only fragments.
 *
 * No ViewPager, no navigation component, no ViewModel. Two screens with no
 * shared state do not justify any of that machinery.
 */
public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Process death while backgrounded wipes the in-memory JWT. Detect it
        // here rather than letting every poll fail with a 401 storm.
        if (!Session.isAuthenticated()) {
            returnToLogin(false);
            return;
        }

        BottomNavigationView nav = findViewById(R.id.bottomNav);
        nav.setOnItemSelectedListener(item -> {
            int id = item.getItemId();
            if (id == R.id.nav_status) {
                show(new StatusFragment());
                return true;
            } else if (id == R.id.nav_threats) {
                show(new ThreatsFragment());
                return true;
            }
            return false;
        });

        if (savedInstanceState == null) {
            nav.setSelectedItemId(R.id.nav_status);
        }
    }

    private void show(Fragment fragment) {
        getSupportFragmentManager()
                .beginTransaction()
                .replace(R.id.fragmentContainer, fragment)
                .commit();
    }

    /** Called by fragments when the backend rejects the token. */
    public void onSessionExpired() {
        returnToLogin(true);
    }

    private void returnToLogin(boolean notify) {
        if (notify) {
            Toast.makeText(this, R.string.error_session_expired, Toast.LENGTH_LONG).show();
        }
        Session.clear();
        Intent i = new Intent(this, LoginActivity.class);
        i.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(i);
        finish();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main_menu, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == R.id.action_logout) {
            returnToLogin(false);
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
