package com.cybershield.app.ui;

import android.graphics.Color;
import android.os.Bundle;
import android.text.format.DateUtils;
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
import com.cybershield.app.data.ScanEntity;
import com.cybershield.app.databinding.ActivityHistoryBinding;

import java.util.ArrayList;
import java.util.List;

public class HistoryActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ActivityHistoryBinding b = ActivityHistoryBinding.inflate(getLayoutInflater());
        setContentView(b.getRoot());

        List<ScanEntity> rows = CyberShieldApp.get().db().scanDao().recent();
        b.empty.setVisibility(rows.isEmpty() ? View.VISIBLE : View.GONE);
        b.list.setLayoutManager(new LinearLayoutManager(this));
        b.list.setAdapter(new Adapter(rows));
    }

    static class Adapter extends RecyclerView.Adapter<Adapter.VH> {
        private final List<ScanEntity> items;

        Adapter(List<ScanEntity> items) { this.items = new ArrayList<>(items); }

        @NonNull @Override
        public VH onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            return new VH(LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_history, parent, false));
        }

        @Override
        public void onBindViewHolder(@NonNull VH h, int position) {
            ScanEntity s = items.get(position);
            h.priority.setText(s.priority);
            h.priority.setTextColor(color(s.riskLevel));
            h.type.setText(s.type + (s.serverChecked ? "" : " · on-device"));
            h.when.setText(DateUtils.getRelativeTimeSpanString(s.createdAt));
            h.snippet.setText(s.snippet);
        }

        @Override public int getItemCount() { return items.size(); }

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

        static class VH extends RecyclerView.ViewHolder {
            final TextView priority, type, when, snippet;
            VH(@NonNull View v) {
                super(v);
                priority = v.findViewById(R.id.hPriority);
                type = v.findViewById(R.id.hType);
                when = v.findViewById(R.id.hWhen);
                snippet = v.findViewById(R.id.hSnippet);
            }
        }
    }
}
