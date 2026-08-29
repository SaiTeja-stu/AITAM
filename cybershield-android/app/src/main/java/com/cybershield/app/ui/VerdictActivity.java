package com.cybershield.app.ui;

import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.view.View;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;

import com.cybershield.app.data.Repository;
import com.cybershield.app.databinding.ActivityVerdictBinding;
import com.cybershield.app.engine.LocalVerdict;
import com.cybershield.app.net.dto.AnalyzeResponse;

/**
 * Shows the on-device verdict instantly, then replaces it with the authoritative
 * server verdict when it arrives. Works offline (local verdict stands).
 */
public class VerdictActivity extends AppCompatActivity {

    private static final String EX_TYPE = "type";
    private static final String EX_CONTENT = "content";
    private static final String EX_SOURCE = "source";

    private ActivityVerdictBinding b;
    private SignalAdapter adapter;
    private String type, content, source;

    public static Intent intent(Context ctx, String type, String content, String source) {
        Intent i = new Intent(ctx, VerdictActivity.class);
        i.putExtra(EX_TYPE, type);
        i.putExtra(EX_CONTENT, content);
        i.putExtra(EX_SOURCE, source);
        return i;
    }

    public static void start(Context ctx, String type, String content, String source) {
        Intent i = intent(ctx, type, content, source);
        if (!(ctx instanceof AppCompatActivity)) i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        ctx.startActivity(i);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        b = ActivityVerdictBinding.inflate(getLayoutInflater());
        setContentView(b.getRoot());

        type = getIntent().getStringExtra(EX_TYPE);
        content = getIntent().getStringExtra(EX_CONTENT);
        source = getIntent().getStringExtra(EX_SOURCE);
        if (type == null || content == null) { finish(); return; }

        adapter = new SignalAdapter();
        b.signals.setLayoutManager(new LinearLayoutManager(this));
        b.signals.setAdapter(adapter);

        b.btnDone.setOnClickListener(v -> finish());
        b.btnReport.setOnClickListener(v -> {
            new Repository(this).report(type, content, "reported from app");
            Toast.makeText(this, "Reported. Thank you.", Toast.LENGTH_SHORT).show();
            b.btnReport.setEnabled(false);
        });

        new Repository(this).analyze(type, content, source, new Repository.Callback() {
            @Override public void onLocal(LocalVerdict local) { renderLocal(local); }
            @Override public void onServer(AnalyzeResponse server) { renderServer(server); }
            @Override public void onServerError(String message) {
                Toast.makeText(VerdictActivity.this, message, Toast.LENGTH_SHORT).show();
            }
        });
    }

    private void renderLocal(LocalVerdict v) {
        b.badge.setText(v.priority() + " · on-device check");
        b.badge.setBackgroundColor(colorForLevel(v.level.name()));
        b.score.setText(String.valueOf(v.score));
        b.score.setTextColor(colorForLevel(v.level.name()));
        b.wording.setText("Preliminary — confirming with the server…");
        b.paymentWarn.setVisibility(v.initiatesPayment ? View.VISIBLE : View.GONE);
        adapter.setReasons(v.reasons);
        b.explanation.setText(v.reasons.isEmpty()
                ? "No obvious problems found on-device. Waiting for the full check."
                : "");
        b.recsTitle.setVisibility(View.GONE);
    }

    private void renderServer(AnalyzeResponse r) {
        boolean noSignals = r.riskScore == 0
                && (r.signals == null || r.signals.stream().noneMatch(s -> s.weight > 0));
        boolean unverifiedClean = "SAFE".equals(r.riskLevel) && !r.trusted && noSignals;

        String badgeText = unverifiedClean ? "UNVERIFIED" : r.priority + " · " + r.riskLevel.replace('_', ' ');
        int color = unverifiedClean ? Color.parseColor("#93A0BC") : colorForLevel(r.riskLevel);
        b.badge.setText(badgeText);
        b.badge.setBackgroundColor(color);
        b.score.setText(String.valueOf(r.riskScore));
        b.score.setTextColor(color);

        if (r.trusted) {
            b.wording.setText("On Cyber Shield's verified safe list — no warning signs.");
        } else if (unverifiedClean) {
            b.wording.setText("No warning signs found — but we could NOT confirm this is safe. "
                    + "Be careful before logging in or paying.");
        } else {
            b.wording.setText("“" + r.wording + "”  ·  " + r.confidence + "% confident");
        }

        b.paymentWarn.setVisibility(r.initiatesPayment ? View.VISIBLE : View.GONE);
        if (r.payment != null) {
            b.paymentBox.setVisibility(View.VISIBLE);
            b.payPayee.setText("To: " + safe(r.payment.payeeName) + "  (" + safe(r.payment.payeeVpa) + ")");
            b.payAmount.setText("Amount: " + (r.payment.amount == null ? "not set" : r.payment.amount + " " + r.payment.currency)
                    + (r.payment.pullPayment ? "  ·  PULL request" : ""));
        }

        b.explanation.setText(r.explanation == null ? "" : r.explanation);
        adapter.set(r.signals);

        b.recsTitle.setVisibility(View.VISIBLE);
        StringBuilder sb = new StringBuilder();
        if (r.recommendations != null) for (String rec : r.recommendations) sb.append("•  ").append(rec).append('\n');
        b.recs.setText(sb.toString().trim());
    }

    private static String safe(String s) {
        return s == null ? "—" : s;
    }

    private int colorForLevel(String level) {
        if (level == null) return Color.parseColor("#93A0BC");
        switch (level) {
            case "MALICIOUS": return Color.parseColor("#F87171");
            case "HIGH_RISK": return Color.parseColor("#FB923C");
            case "SUSPICIOUS": return Color.parseColor("#FDE047");
            case "SAFE": return Color.parseColor("#34D399");
            default: return Color.parseColor("#93A0BC");
        }
    }
}
