package com.cybershield.app.ui;

import android.graphics.Color;
import android.text.format.DateUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.cybershield.app.R;
import com.cybershield.app.data.ScanEntity;

import java.util.ArrayList;
import java.util.List;

public class RecentAdapter extends RecyclerView.Adapter<RecentAdapter.VH> {

    private final List<ScanEntity> items = new ArrayList<>();

    public void set(List<ScanEntity> list) {
        items.clear();
        if (list != null) items.addAll(list);
        notifyDataSetChanged();
    }

    static int color(String level) {
        if (level == null) return Color.parseColor("#93A0BC");
        switch (level) {
            case "MALICIOUS": return Color.parseColor("#F87171");
            case "HIGH_RISK": return Color.parseColor("#FB923C");
            case "SUSPICIOUS": return Color.parseColor("#FDE047");
            case "SAFE": return Color.parseColor("#34D399");
            default: return Color.parseColor("#93A0BC");
        }
    }

    @NonNull @Override
    public VH onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        return new VH(LayoutInflater.from(parent.getContext()).inflate(R.layout.item_recent, parent, false));
    }

    @Override
    public void onBindViewHolder(@NonNull VH h, int position) {
        ScanEntity s = items.get(position);
        h.priority.setText(s.priority == null ? "" : s.priority);
        h.priority.setTextColor(color(s.riskLevel));
        h.snippet.setText(s.snippet == null || s.snippet.isEmpty() ? "(no preview)" : s.snippet);
        String when = DateUtils.getRelativeTimeSpanString(s.createdAt).toString();
        h.meta.setText(s.type + " · " + when + (s.serverChecked ? "" : " · on-device"));
    }

    @Override public int getItemCount() { return items.size(); }

    static class VH extends RecyclerView.ViewHolder {
        final TextView priority, snippet, meta;
        VH(@NonNull View v) {
            super(v);
            priority = v.findViewById(R.id.rPriority);
            snippet = v.findViewById(R.id.rSnippet);
            meta = v.findViewById(R.id.rMeta);
        }
    }
}
