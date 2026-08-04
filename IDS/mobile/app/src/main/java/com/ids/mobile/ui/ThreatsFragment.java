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
import com.ids.mobile.model.FlaggedIp;
import com.ids.mobile.util.Poller;
import com.ids.mobile.util.TimeFormat;

import java.util.List;

/**
 * Threat actors / top source IPs. Polls GET /api/alerts/flagged-ips every 10s.
 *
 * Slower cadence than the health screen on purpose: this endpoint aggregates
 * over alert history and is heavier than a status ping, while the underlying
 * data changes far more slowly than a health flag does. Polling it as fast as
 * health would cost the backend real work for no extra information.
 */
public class ThreatsFragment extends Fragment {

    private static final long POLL_SECONDS = 10;

    private SwipeRefreshLayout swipe;
    private TextView tvUpdated, tvEmpty;
    private ThreatAdapter adapter;

    private final Poller poller = new Poller("ids-threats-poller", POLL_SECONDS);

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        View v = inflater.inflate(R.layout.fragment_list, container, false);

        swipe     = v.findViewById(R.id.swipe);
        tvUpdated = v.findViewById(R.id.tvUpdated);
        tvEmpty   = v.findViewById(R.id.tvEmpty);
        v.findViewById(R.id.tvCaveat).setVisibility(View.GONE);

        RecyclerView rv = v.findViewById(R.id.recycler);
        rv.setLayoutManager(new LinearLayoutManager(getContext()));
        adapter = new ThreatAdapter();
        rv.setAdapter(adapter);

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
        poller.stop();
    }

    private void restartPolling() {
        final ApiClient client = Session.client();
        if (client == null) {
            handleAuthFailure();
            return;
        }

        poller.start(client::fetchFlaggedIps, new Poller.Callback<List<FlaggedIp>>() {
            @Override
            public void onSuccess(List<FlaggedIp> result) {
                if (!isAdded()) return;
                swipe.setRefreshing(false);
                adapter.submit(result);
                if (result.isEmpty()) {
                    tvEmpty.setText(R.string.empty_threats);
                    tvEmpty.setVisibility(View.VISIBLE);
                } else {
                    tvEmpty.setVisibility(View.GONE);
                }
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
                tvUpdated.setText(getString(R.string.update_failed, e.getMessage()));
                if (adapter.getItemCount() == 0) {
                    tvEmpty.setText(R.string.empty_threats);
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
