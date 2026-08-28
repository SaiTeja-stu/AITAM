package com.cybershield.app.ui;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.cybershield.app.CyberShieldApp;
import com.cybershield.app.R;
import com.cybershield.app.databinding.ActivityReportsBinding;
import com.cybershield.app.net.dto.Page;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

/** Admin: moderate user threat reports. Confirm pushes the indicator to the live blocklist. */
public class ReportsActivity extends AppCompatActivity {

    private ActivityReportsBinding b;
    private final Adapter adapter = new Adapter();
    private String status = "PENDING";

    @Override
    protected void onCreate(Bundle s) {
        super.onCreate(s);
        b = ActivityReportsBinding.inflate(getLayoutInflater());
        setContentView(b.getRoot());

        b.list.setLayoutManager(new LinearLayoutManager(this));
        b.list.setAdapter(adapter);
        adapter.onAct = (id, confirm) -> act(id, confirm);

        b.tabs.setOnCheckedStateChangeListener((g, ids) -> {
            int id = b.tabs.getCheckedChipId();
            status = id == b.tConfirmed.getId() ? "CONFIRMED"
                    : id == b.tRejected.getId() ? "REJECTED" : "PENDING";
            load();
        });
        load();
    }

    private void load() {
        b.empty.setText("Loading…");
        b.empty.setVisibility(View.VISIBLE);
        CyberShieldApp.get().api().api().adminReports(status, 0, 50).enqueue(new Callback<>() {
            @Override public void onResponse(@NonNull Call<Page<Page.ReportItem>> c, @NonNull Response<Page<Page.ReportItem>> r) {
                if (r.code() == 403) {
                    b.empty.setText("Admin access required. Sign in with an admin account to moderate reports.");
                    b.tabs.setVisibility(View.GONE);
                    adapter.set(null);
                    return;
                }
                List<Page.ReportItem> items = r.isSuccessful() && r.body() != null ? r.body().items : null;
                adapter.set(items);
                boolean empty = items == null || items.isEmpty();
                b.empty.setText(empty ? "No reports here." : "");
                b.empty.setVisibility(empty ? View.VISIBLE : View.GONE);
            }
            @Override public void onFailure(@NonNull Call<Page<Page.ReportItem>> c, @NonNull Throwable t) {
                b.empty.setText("Couldn't load — is the backend reachable?");
            }
        });
    }

    private void act(String id, boolean confirm) {
        Call<Map<String, Object>> call = confirm
                ? CyberShieldApp.get().api().api().confirmReport(id)
                : CyberShieldApp.get().api().api().rejectReport(id);
        call.enqueue(new Callback<>() {
            @Override public void onResponse(@NonNull Call<Map<String, Object>> c, @NonNull Response<Map<String, Object>> r) {
                Toast.makeText(ReportsActivity.this,
                        r.isSuccessful() ? (confirm ? "Confirmed — added to blocklist" : "Rejected") : "Failed",
                        Toast.LENGTH_SHORT).show();
                load();
            }
            @Override public void onFailure(@NonNull Call<Map<String, Object>> c, @NonNull Throwable t) {
                Toast.makeText(ReportsActivity.this, "Network error", Toast.LENGTH_SHORT).show();
            }
        });
    }

    interface OnAct { void run(String id, boolean confirm); }

    static class Adapter extends RecyclerView.Adapter<Adapter.VH> {
        private final List<Page.ReportItem> items = new ArrayList<>();
        OnAct onAct;

        void set(List<Page.ReportItem> l) { items.clear(); if (l != null) items.addAll(l); notifyDataSetChanged(); }

        @NonNull @Override public VH onCreateViewHolder(@NonNull ViewGroup p, int v) {
            return new VH(LayoutInflater.from(p.getContext()).inflate(R.layout.item_report, p, false));
        }
        @Override public void onBindViewHolder(@NonNull VH h, int i) {
            Page.ReportItem r = items.get(i);
            String ind = r.indicatorType == null ? "" : "  ·  " + r.indicatorType + ": " + r.indicatorValue;
            h.meta.setText(r.type + "  ·  " + r.status + ind);
            h.snippet.setText((r.snippet == null ? "" : r.snippet)
                    + (r.note == null || r.note.isEmpty() ? "" : "\nnote: " + r.note));
            boolean pending = "PENDING".equals(r.status);
            h.actions.setVisibility(pending ? View.VISIBLE : View.GONE);
            h.confirm.setOnClickListener(v -> { if (onAct != null) onAct.run(r.id, true); });
            h.reject.setOnClickListener(v -> { if (onAct != null) onAct.run(r.id, false); });
        }
        @Override public int getItemCount() { return items.size(); }

        static class VH extends RecyclerView.ViewHolder {
            final TextView meta, snippet;
            final View actions;
            final com.google.android.material.button.MaterialButton confirm, reject;
            VH(@NonNull View v) {
                super(v);
                meta = v.findViewById(R.id.rpMeta);
                snippet = v.findViewById(R.id.rpSnippet);
                actions = v.findViewById(R.id.rpActions);
                confirm = v.findViewById(R.id.rpConfirm);
                reject = v.findViewById(R.id.rpReject);
            }
        }
    }
}
