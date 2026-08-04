package com.ids.mobile.ui;

import android.graphics.drawable.GradientDrawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.RecyclerView;

import com.ids.mobile.R;
import com.ids.mobile.model.HealthComponent;

import java.util.ArrayList;
import java.util.List;

public class HealthAdapter extends RecyclerView.Adapter<HealthAdapter.VH> {

    private final List<HealthComponent> items = new ArrayList<>();

    /**
     * The list is small (7 fixed rows) and fully replaced each poll, so
     * notifyDataSetChanged is correct here. DiffUtil would be ceremony for
     * seven rows that all change at once.
     */
    public void submit(List<HealthComponent> newItems) {
        items.clear();
        items.addAll(newItems);
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public VH onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View v = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_health, parent, false);
        return new VH(v);
    }

    @Override
    public void onBindViewHolder(@NonNull VH h, int position) {
        HealthComponent c = items.get(position);

        h.tvName.setText(c.name);
        h.tvStatus.setText(c.status);
        h.tvDetail.setText(c.detail);
        h.tvDetail.setVisibility(c.detail.isEmpty() ? View.GONE : View.VISIBLE);

        int color = ContextCompat.getColor(h.itemView.getContext(), colorFor(c.status));
        // Tint the shared dot drawable per-row. mutate() is essential: without
        // it every row would share one drawable instance and the last bind
        // would recolor the entire list.
        GradientDrawable dot = (GradientDrawable) h.vDot.getBackground().mutate();
        dot.setColor(color);
        h.tvStatus.setTextColor(color);
    }

    private int colorFor(String status) {
        switch (status) {
            case "OK":    return R.color.status_ok;
            case "WARN":  return R.color.status_warn;
            case "ERROR": return R.color.status_error;
            default:      return R.color.status_unknown;
        }
    }

    @Override
    public int getItemCount() { return items.size(); }

    static class VH extends RecyclerView.ViewHolder {
        final View vDot;
        final TextView tvName, tvStatus, tvDetail;

        VH(@NonNull View v) {
            super(v);
            vDot     = v.findViewById(R.id.vDot);
            tvName   = v.findViewById(R.id.tvName);
            tvStatus = v.findViewById(R.id.tvStatus);
            tvDetail = v.findViewById(R.id.tvDetail);
        }
    }
}
