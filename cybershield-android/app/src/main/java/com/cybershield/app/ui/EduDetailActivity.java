package com.cybershield.app.ui;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.cybershield.app.R;

import java.util.ArrayList;

/** Shows one awareness module. Data passed via intent extras (no network needed). */
public class EduDetailActivity extends AppCompatActivity {

    public static Intent intent(Context ctx, EduAdapter.Module m) {
        Intent i = new Intent(ctx, EduDetailActivity.class);
        i.putExtra("title", m.title);
        i.putExtra("summary", m.summary);
        i.putStringArrayListExtra("keyPoints", new ArrayList<>(m.keyPoints));
        i.putStringArrayListExtra("redFlags", new ArrayList<>(m.redFlags));
        return i;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (20 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);
        root.setBackgroundColor(getColor(R.color.ink));

        root.addView(text(getIntent().getStringExtra("title"), 22, true));
        root.addView(text(getIntent().getStringExtra("summary"), 15, false));

        root.addView(heading("Key points"));
        for (String s : list("keyPoints")) root.addView(bullet(s, R.color.text));

        root.addView(heading("Red flags"));
        for (String s : list("redFlags")) root.addView(bullet(s, R.color.risk_malicious));

        ScrollView sv = new ScrollView(this);
        sv.addView(root);
        setContentView(sv);
    }

    private java.util.List<String> list(String key) {
        java.util.ArrayList<String> l = getIntent().getStringArrayListExtra(key);
        return l == null ? new ArrayList<>() : l;
    }

    private TextView text(String s, int sp, boolean bold) {
        TextView t = new TextView(this);
        t.setText(s == null ? "" : s);
        t.setTextSize(sp);
        t.setTextColor(getColor(R.color.text));
        if (bold) t.setTypeface(t.getTypeface(), android.graphics.Typeface.BOLD);
        int m = (int) (6 * getResources().getDisplayMetrics().density);
        t.setPadding(0, m, 0, m);
        return t;
    }

    private TextView heading(String s) {
        TextView t = text(s.toUpperCase(), 12, true);
        t.setTextColor(getColor(R.color.muted));
        int m = (int) (16 * getResources().getDisplayMetrics().density);
        t.setPadding(0, m, 0, 4);
        return t;
    }

    private TextView bullet(String s, int colorRes) {
        TextView t = new TextView(this);
        t.setText("•  " + s);
        t.setTextSize(14);
        t.setTextColor(getColor(colorRes));
        int m = (int) (3 * getResources().getDisplayMetrics().density);
        t.setPadding(0, m, 0, m);
        return t;
    }
}
