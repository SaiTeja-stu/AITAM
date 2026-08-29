package com.cybershield.app.ui;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.cybershield.app.R;

import java.util.ArrayList;
import java.util.List;

public class EduAdapter extends RecyclerView.Adapter<EduAdapter.VH> {

    public static class Module {
        public String id, icon, title, rule, summary, category;
        public List<String> doThis = new ArrayList<>();
        public List<String> redFlags = new ArrayList<>();
        public List<String> keyPoints = new ArrayList<>();   // legacy field, still parsed

        public List<String> safeActions() {
            return (doThis != null && !doThis.isEmpty()) ? doThis : keyPoints;
        }
    }

    /** Topic icon (line-art, no emoji). */
    public static int iconFor(String id) {
        if (id == null) return R.drawable.ic_shield;
        switch (id) {
            case "otp-fraud":       return R.drawable.ic_edu_otp;
            case "upi-qr-safety":   return R.drawable.ic_edu_pay;
            case "phishing-links":  return R.drawable.ic_edu_phish;
            case "fake-website":    return R.drawable.ic_edu_web;
            case "digital-arrest":  return R.drawable.ic_edu_arrest;
            case "prize-job-scams": return R.drawable.ic_edu_prize;
            default:                return R.drawable.ic_shield;
        }
    }

    public interface OnClick { void open(Module m); }

    private final List<Module> items = new ArrayList<>();
    private final OnClick onClick;

    public EduAdapter(OnClick onClick) { this.onClick = onClick; }

    public void set(List<Module> list) {
        items.clear();
        if (list != null) items.addAll(list);
        notifyDataSetChanged();
    }

    @NonNull @Override
    public VH onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        return new VH(LayoutInflater.from(parent.getContext()).inflate(R.layout.item_edu, parent, false));
    }

    @Override
    public void onBindViewHolder(@NonNull VH h, int position) {
        Module m = items.get(position);
        h.icon.setImageResource(iconFor(m.id));
        h.title.setText(m.title);
        h.summary.setText(m.rule != null && !m.rule.isEmpty() ? m.rule : m.summary);
        h.itemView.setOnClickListener(v -> onClick.open(m));
    }

    @Override public int getItemCount() { return items.size(); }

    static class VH extends RecyclerView.ViewHolder {
        final ImageView icon;
        final TextView title, summary;
        VH(@NonNull View v) {
            super(v);
            icon = v.findViewById(R.id.eIcon);
            title = v.findViewById(R.id.eTitle);
            summary = v.findViewById(R.id.eSummary);
        }
    }
}
