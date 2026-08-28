package com.cybershield.app.ui;

import android.graphics.Color;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.cybershield.app.R;
import com.cybershield.app.net.dto.AnalyzeResponse;

import java.util.ArrayList;
import java.util.List;

public class SignalAdapter extends RecyclerView.Adapter<SignalAdapter.VH> {

    private final List<AnalyzeResponse.Signal> items = new ArrayList<>();

    public void set(List<AnalyzeResponse.Signal> list) {
        items.clear();
        if (list != null) items.addAll(list);
        notifyDataSetChanged();
    }

    /** Build synthetic signals from a local-only verdict (list of reason strings). */
    public void setReasons(List<String> reasons) {
        items.clear();
        if (reasons != null) {
            for (String r : reasons) {
                AnalyzeResponse.Signal s = new AnalyzeResponse.Signal();
                s.name = r;
                s.severity = "HIGH";
                items.add(s);
            }
        }
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public VH onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View v = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_signal, parent, false);
        return new VH(v);
    }

    @Override
    public void onBindViewHolder(@NonNull VH h, int position) {
        AnalyzeResponse.Signal s = items.get(position);
        h.name.setText(s.name);
        h.detail.setText(s.detail == null ? "" : s.detail);
        h.detail.setVisibility(s.detail == null || s.detail.isEmpty() ? View.GONE : View.VISIBLE);
        h.severity.setText(s.severity == null ? "" : s.severity);
        h.severity.setTextColor(colorFor(s.severity));
    }

    private int colorFor(String sev) {
        if (sev == null) return Color.GRAY;
        switch (sev) {
            case "CRITICAL": return Color.parseColor("#F87171");
            case "HIGH": return Color.parseColor("#FB923C");
            case "MEDIUM": return Color.parseColor("#FDE047");
            case "TRUST": return Color.parseColor("#34D399");
            default: return Color.parseColor("#93A0BC");
        }
    }

    @Override
    public int getItemCount() {
        return items.size();
    }

    static class VH extends RecyclerView.ViewHolder {
        final TextView severity, name, detail;
        VH(@NonNull View v) {
            super(v);
            severity = v.findViewById(R.id.sigSeverity);
            name = v.findViewById(R.id.sigName);
            detail = v.findViewById(R.id.sigDetail);
        }
    }
}
