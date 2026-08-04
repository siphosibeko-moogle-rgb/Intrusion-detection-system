package com.ids.mobile.ui;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;

import com.ids.mobile.R;
import com.ids.mobile.api.ApiClient;
import com.ids.mobile.api.AuthExpiredException;
import com.ids.mobile.api.Session;
import com.ids.mobile.model.HealthComponent;
import com.ids.mobile.util.Poller;
import com.ids.mobile.util.TimeFormat;

import java.util.List;

/** Sensor / engine status. Polls GET /api/dashboard/health every 5s. */
public class StatusFragment extends Fragment {

    private static final long POLL_SECONDS = 5;

    private SwipeRefreshLayout swipe;
    private TextView tvUpdated, tvEmpty, tvCaveat;
    private HealthAdapter adapter;

    private final Poller poller = new Poller("ids-health-poller", POLL_SECONDS);

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        View v = inflater.inflate(R.layout.fragment_list, container, false);

        swipe     = v.findViewById(R.id.swipe);
        tvUpdated = v.findViewById(R.id.tvUpdated);
        tvEmpty   = v.findViewById(R.id.tvEmpty);
        tvCaveat  = v.findViewById(R.id.tvCaveat);

        RecyclerView rv = v.findViewById(R.id.recycler);
        rv.setLayoutManager(new LinearLayoutManager(getContext()));
        adapter = new HealthAdapter();
        rv.setAdapter(adapter);

        // Honesty in the UI: see DashboardController.health(). Without this
        // line a green "Packet Capture" dot silently means "an alert arrived
        // recently", which is NOT the same as "the sensor is alive".
        tvCaveat.setText(R.string.caveat_capture_proxy);
        tvCaveat.setVisibility(View.VISIBLE);

        // Pull-to-refresh just restarts the poller, which fires immediately.
        swipe.setOnRefreshListener(this::restartPolling);
        return v;
    }

    @Override
    public void onResume() {
        super.onResume();
        restartPolling();
    }

    @Override
    public void onPause() {
        super.onPause();
        poller.stop();          // the leak guard: no background polling off-screen
    }

    private void restartPolling() {
        final ApiClient client = Session.client();
        if (client == null) {
            handleAuthFailure();
            return;
        }

        poller.start(client::fetchHealth, new Poller.Callback<List<HealthComponent>>() {
            @Override
            public void onSuccess(List<HealthComponent> result) {
                if (!isAdded()) return;      // view is gone; drop the result
                swipe.setRefreshing(false);
                adapter.submit(result);
                tvEmpty.setVisibility(result.isEmpty() ? View.VISIBLE : View.GONE);
                tvUpdated.setText(getString(R.string.updated_at, TimeFormat.nowClock()));
            }

            @Override
            public void onError(Exception e) {
                if (!isAdded()) return;
                swipe.setRefreshing(false);
                if (e instanceof AuthExpiredException) {
                    handleAuthFailure();
                    return;
                }
                // Keep the last known good data on screen and mark it stale.
                // Blanking the list on every transient network blip would make
                // the app useless on flaky wifi.
                tvUpdated.setText(getString(R.string.update_failed, e.getMessage()));
                if (adapter.getItemCount() == 0) {
                    tvEmpty.setText(R.string.empty_health);
                    tvEmpty.setVisibility(View.VISIBLE);
                }
            }
        });
    }

    private void handleAuthFailure() {
        poller.stop();
        if (getActivity() instanceof MainActivity) {
            ((MainActivity) getActivity()).onSessionExpired();
        }
    }
}
