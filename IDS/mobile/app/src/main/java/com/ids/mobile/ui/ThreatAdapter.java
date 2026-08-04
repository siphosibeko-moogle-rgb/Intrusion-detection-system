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
import com.ids.mobile.model.FlaggedIp;
import com.ids.mobile.util.TimeFormat;

import java.util.ArrayList;
import java.util.List;

public class ThreatAdapter extends RecyclerView.Adapter<ThreatAdapter.VH> {

    private final List<FlaggedIp> items = new ArrayList<>();

    public void submit(List<FlaggedIp> newItems) {
        items.clear();
        items.addAll(newItems);
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public VH onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View v = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_threat, parent, false);
        return new VH(v);
    }

    @Override
    public void onBindViewHolder(@NonNull VH h, int position) {
        FlaggedIp f = items.get(position);

        h.tvIp.setText(f.ip);
        h.tvOrigin.setText(f.describeOrigin());
        h.tvHits.setText(h.itemView.getContext().getString(R.string.hits_count, f.hits));
        h.tvLastSeen.setText(TimeFormat.relative(f.lastSeen));

        String threat = f.threatType == null || f.threatType.isEmpty() ? "-" : f.threatType;
        if (f.protocol != null && !f.protocol.isEmpty()) threat = threat + "  \u00b7  " + f.protocol;
        h.tvThreat.setText(threat);

        String sev = f.severity.isEmpty() ? "UNKNOWN" : f.severity;
        h.tvSeverity.setText(sev);
        int color = ContextCompat.getColor(h.itemView.getContext(), colorFor(sev));
        GradientDrawable chip = (GradientDrawable) h.tvSeverity.getBackground().mutate();
        chip.setColor(color);
    }

    private int colorFor(String severity) {
        switch (severity) {
            case "CRITICAL": return R.color.sev_critical;
            case "HIGH":     return R.color.sev_high;
            case "MEDIUM":   return R.color.sev_medium;
            case "LOW":      return R.color.sev_low;
            default:         return R.color.status_unknown;
        }
    }

    @Override
    public int getItemCount() { return items.size(); }

    static class VH extends RecyclerView.ViewHolder {
        final TextView tvIp, tvOrigin, tvSeverity, tvHits, tvThreat, tvLastSeen;

        VH(@NonNull View v) {
            super(v);
            tvIp       = v.findViewById(R.id.tvIp);
            tvOrigin   = v.findViewById(R.id.tvOrigin);
            tvSeverity = v.findViewById(R.id.tvSeverity);
            tvHits     = v.findViewById(R.id.tvHits);
            tvThreat   = v.findViewById(R.id.tvThreat);
            tvLastSeen = v.findViewById(R.id.tvLastSeen);
        }
    }
}
