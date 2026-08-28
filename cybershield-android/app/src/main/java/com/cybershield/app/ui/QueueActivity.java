package com.cybershield.app.ui;

import android.graphics.Color;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.cybershield.app.CyberShieldApp;
import com.cybershield.app.R;
import com.cybershield.app.databinding.ActivityQueueBinding;
import com.cybershield.app.net.dto.Page;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

/**
 * Recent analyses. Admins see everyone's (via /api/v1/admin/scans); regular
 * users see their own (/api/v1/history).
 */
public class QueueActivity extends AppCompatActivity {

    private ActivityQueueBinding b;
    private final Adapter adapter = new Adapter();
    private boolean admin;
    private String level = "";

    @Override
    protected void onCreate(Bundle s) {
        super.onCreate(s);
        b = ActivityQueueBinding.inflate(getLayoutInflater());
        setContentView(b.getRoot());

        admin = getIntent().getBooleanExtra("admin", false);
        b.subtitle.setText(admin ? "Recent analyses across all users" : "Your recent checks");
        b.list.setLayoutManager(new LinearLayoutManager(this));
        b.list.setAdapter(adapter);

        b.filters.setOnCheckedStateChangeListener((g, ids) -> {
            int id = b.filters.getCheckedChipId();
            if (id == b.fMal.getId()) level = "MALICIOUS";
            else if (id == b.fHigh.getId()) level = "HIGH_RISK";
            else if (id == b.fSus.getId()) level = "SUSPICIOUS";
            else if (id == b.fSafe.getId()) level = "SAFE";
            else level = "";
            load();
        });
        load();
    }

    private void load() {
        b.empty.setText("Loading…");
        b.empty.setVisibility(View.VISIBLE);
        if (admin) {
            CyberShieldApp.get().api().api().adminScans(level.isEmpty() ? null : level, 0, 50)
                    .enqueue(new Callback<>() {
                        @Override public void onResponse(@NonNull Call<Page<Page.ScanItem>> c, @NonNull Response<Page<Page.ScanItem>> r) {
                            show(r.isSuccessful() && r.body() != null ? r.body().items : null);
                        }
                        @Override public void onFailure(@NonNull Call<Page<Page.ScanItem>> c, @NonNull Throwable t) { fail(); }
                    });
        } else {
            CyberShieldApp.get().api().api().myHistory(0, 50).enqueue(new Callback<>() {
                @Override public void onResponse(@NonNull Call<Map<String, Object>> c, @NonNull Response<Map<String, Object>> r) {
                    List<Page.ScanItem> items = new ArrayList<>();
                    if (r.isSuccessful() && r.body() != null && r.body().get("items") instanceof List<?> raw) {
                        com.google.gson.Gson g = new com.google.gson.Gson();
                        for (Object o : raw) {
                            Page.ScanItem it = g.fromJson(g.toJson(o), Page.ScanItem.class);
                            if (level.isEmpty() || level.equals(it.riskLevel)) items.add(it);
                        }
                    }
                    show(items);
                }
                @Override public void onFailure(@NonNull Call<Map<String, Object>> c, @NonNull Throwable t) { fail(); }
            });
        }
    }

    private void show(List<Page.ScanItem> items) {
        adapter.set(items);
        boolean empty = items == null || items.isEmpty();
        b.empty.setText(empty ? "Nothing here yet." : "");
        b.empty.setVisibility(empty ? View.VISIBLE : View.GONE);
    }

    private void fail() {
        b.empty.setText("Couldn't load — is the backend reachable?");
        b.empty.setVisibility(View.VISIBLE);
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

    static class Adapter extends RecyclerView.Adapter<Adapter.VH> {
        private final List<Page.ScanItem> items = new ArrayList<>();
        void set(List<Page.ScanItem> l) { items.clear(); if (l != null) items.addAll(l); notifyDataSetChanged(); }

        @NonNull @Override public VH onCreateViewHolder(@NonNull ViewGroup p, int v) {
            return new VH(LayoutInflater.from(p.getContext()).inflate(R.layout.item_recent, p, false));
        }
        @Override public void onBindViewHolder(@NonNull VH h, int i) {
            Page.ScanItem s = items.get(i);
            h.priority.setText(s.priority);
            h.priority.setTextColor(color(s.riskLevel));
            h.snippet.setText(s.snippet == null || s.snippet.isEmpty() ? "(no preview)" : s.snippet);
            h.meta.setText(s.type + " · score " + s.riskScore + " · conf " + s.confidence);
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
}
