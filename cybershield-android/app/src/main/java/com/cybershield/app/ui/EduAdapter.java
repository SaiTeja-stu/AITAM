package com.cybershield.app.ui;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.cybershield.app.R;

import java.util.ArrayList;
import java.util.List;

public class EduAdapter extends RecyclerView.Adapter<EduAdapter.VH> {

    public static class Module {
        public String id, title, summary, category;
        public List<String> keyPoints = new ArrayList<>();
        public List<String> redFlags = new ArrayList<>();
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
        h.title.setText(m.title);
        h.summary.setText(m.summary);
        h.itemView.setOnClickListener(v -> onClick.open(m));
    }

    @Override public int getItemCount() { return items.size(); }

    static class VH extends RecyclerView.ViewHolder {
        final TextView title, summary;
        VH(@NonNull View v) {
            super(v);
            title = v.findViewById(R.id.eTitle);
            summary = v.findViewById(R.id.eSummary);
        }
    }
}
