package com.cybershield.app.ui;

import android.content.ContentValues;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.MediaStore;
import android.view.View;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import com.cybershield.app.CyberShieldApp;
import com.cybershield.app.data.Repository;
import com.cybershield.app.databinding.ActivityForensicsBinding;
import com.cybershield.app.geo.LocationHelper;
import com.cybershield.app.net.dto.ForensicsResult;
import com.cybershield.app.net.dto.IncidentReportResponse;

import java.io.IOException;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import okhttp3.ResponseBody;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

/**
 * SIH26106 showcase screen: paste a raw .eml, get hop-by-hop relay
 * reconstruction with real IP geolocation, SPF/DKIM/DMARC verification,
 * cross-email campaign correlation, and a downloadable Section 65B forensic
 * evidence PDF — all backed by the live backend, not simulated on-device.
 */
public class ForensicsActivity extends AppCompatActivity {

    private static final int RC_LOCATION = 4301;

    private ActivityForensicsBinding b;
    private ForensicsResult lastResult;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        b = ActivityForensicsBinding.inflate(getLayoutInflater());
        setContentView(b.getRoot());

        b.btnBack.setOnClickListener(v -> finish());
        b.btnLoadSample.setOnClickListener(v -> loadSample());
        b.btnAnalyze.setOnClickListener(v -> runAnalysis());
        b.btnReportForensic.setOnClickListener(v -> lodgeIncident());
        b.btnDownloadPdf.setOnClickListener(v -> downloadPdf());
    }

    private void loadSample() {
        CyberShieldApp.get().api().api().forensicsSamples().enqueue(new Callback<>() {
            @Override public void onResponse(retrofit2.Call<List<Map<String, String>>> call,
                                              Response<List<Map<String, String>>> resp) {
                if (resp.isSuccessful() && resp.body() != null && !resp.body().isEmpty()) {
                    b.etEml.setText(resp.body().get(0).get("content"));
                } else {
                    Toast.makeText(ForensicsActivity.this, "Could not load sample — is the backend reachable?", Toast.LENGTH_LONG).show();
                }
            }
            @Override public void onFailure(retrofit2.Call<List<Map<String, String>>> call, Throwable t) {
                Toast.makeText(ForensicsActivity.this, "Backend unreachable: " + t.getMessage(), Toast.LENGTH_LONG).show();
            }
        });
    }

    private void runAnalysis() {
        String eml = b.etEml.getText() == null ? "" : b.etEml.getText().toString().trim();
        if (eml.isEmpty()) {
            Toast.makeText(this, "Paste a raw .eml first, or load a sample.", Toast.LENGTH_SHORT).show();
            return;
        }
        b.progress.setVisibility(View.VISIBLE);
        b.resultBox.setVisibility(View.GONE);

        Map<String, String> body = new HashMap<>();
        body.put("rawEml", eml);
        CyberShieldApp.get().api().api().analyzeForensicsRaw(body).enqueue(new Callback<>() {
            @Override public void onResponse(Call<ForensicsResult> call, Response<ForensicsResult> resp) {
                b.progress.setVisibility(View.GONE);
                if (resp.isSuccessful() && resp.body() != null) {
                    lastResult = resp.body();
                    render(lastResult);
                } else {
                    Toast.makeText(ForensicsActivity.this, "Analysis failed (HTTP " + resp.code() + ")", Toast.LENGTH_LONG).show();
                }
            }
            @Override public void onFailure(Call<ForensicsResult> call, Throwable t) {
                b.progress.setVisibility(View.GONE);
                Toast.makeText(ForensicsActivity.this,
                        "Could not reach the backend. Check Auth screen -> Server setting. (" + t.getMessage() + ")",
                        Toast.LENGTH_LONG).show();
            }
        });
    }

    private void render(ForensicsResult r) {
        b.resultBox.setVisibility(View.VISIBLE);
        b.tvRiskBadge.setText(r.riskTier + "  ·  Risk " + r.overallRiskScore + "/100");
        b.tvRiskBadge.setTextColor(colorFor(r.riskTier));

        StringBuilder sb = new StringBuilder();
        sb.append("From: ").append(r.fromDisplay).append(" <").append(r.fromAddress).append(">\n");
        sb.append("Domain: ").append(r.fromDomain).append("\n");
        sb.append("Subject: ").append(r.subject).append("\n");
        sb.append("Evidence SHA-256: ").append(r.evidenceSha256).append("\n\n");

        sb.append("── AUTHENTICATION ──\n");
        if (r.authMatrix != null) {
            for (Map.Entry<String, ForensicsResult.AuthStatus> e : r.authMatrix.entrySet()) {
                sb.append(e.getKey()).append(": ").append(e.getValue().status)
                        .append("\n   ").append(e.getValue().details).append('\n');
            }
        }

        sb.append("\n── RELAY PATH & GEOLOCATION ──\n");
        if (r.relayHops != null) {
            for (ForensicsResult.RelayHop hop : r.relayHops) {
                sb.append("Hop ").append(hop.hopNumber).append(": ").append(hop.ip);
                if (hop.geo != null) {
                    sb.append("  →  ").append(hop.geo.city).append(", ").append(hop.geo.country)
                            .append("  (").append(hop.geo.isp).append(')');
                    if (hop.geo.isTorOrProxy) sb.append("  [TOR/PROXY]");
                    if (hop.geo.isDatacenter) sb.append("  [DATACENTER]");
                }
                if (hop.isOriginating) sb.append("  ★ ORIGIN");
                sb.append('\n');
            }
        }

        sb.append("\n── RISK FACTORS ──\n");
        if (r.riskFactors == null || r.riskFactors.isEmpty()) {
            sb.append("(none)\n");
        } else {
            for (String f : r.riskFactors) sb.append("• ").append(f).append('\n');
        }

        sb.append("\n── CAMPAIGN CORRELATION ──\n");
        if (r.campaignMatches == null || r.campaignMatches.isEmpty()) {
            sb.append("No prior incidents from this domain/IP in case history yet.\n");
        } else {
            for (ForensicsResult.CampaignMatch m : r.campaignMatches) {
                sb.append("• ").append(m.matchedOn).append(" — seen ").append(m.seenAt)
                        .append(" (").append(m.riskTier).append(")\n");
            }
        }

        b.tvResult.setText(sb.toString());
    }

    private int colorFor(String tier) {
        if (tier == null) return Color.parseColor("#9F9F9F");
        switch (tier) {
            case "MALICIOUS": return Color.parseColor("#E5484D");
            case "HIGH_RISK": return Color.parseColor("#F08A3C");
            case "SUSPICIOUS": return Color.parseColor("#F5C451");
            default: return Color.parseColor("#1BD671");
        }
    }

    private void lodgeIncident() {
        if (lastResult == null) return;
        if (!LocationHelper.hasPermission(this)) {
            LocationHelper.requestPermission(this, RC_LOCATION);
            return;
        }
        LocationHelper.fetchCurrentLocation(this, new LocationHelper.Callback() {
            @Override public void onLocation(double lat, double lon, float accuracyMeters, String provider) {
                submitIncident(lat, lon, accuracyMeters, provider);
            }
            @Override public void onUnavailable(String reason) {
                submitIncident(0.0, 0.0, 0f, "UNKNOWN");
            }
        });
    }

    private void submitIncident(double lat, double lon, float accuracyMeters, String provider) {
        new Repository(this).reportIncident(
                "EMAIL", lastResult.evidenceSha256, lastResult.riskTier, lastResult.overallRiskScore,
                lat, lon, accuracyMeters, provider, new Repository.IncidentCallback() {
                    @Override public void onLodged(IncidentReportResponse resp) {
                        new AlertDialog.Builder(ForensicsActivity.this)
                                .setTitle("Incident lodged")
                                .setMessage("Incident ID: " + resp.incidentId
                                        + "\nJurisdiction: " + resp.jurisdictionStation
                                        + "\nHelpline: " + resp.helpline)
                                .setPositiveButton("OK", null)
                                .show();
                    }
                    @Override public void onFailed(String message) {
                        Toast.makeText(ForensicsActivity.this, message, Toast.LENGTH_SHORT).show();
                    }
                });
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == RC_LOCATION) {
            boolean granted = grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED;
            if (granted) lodgeIncident();
            else submitIncident(0.0, 0.0, 0f, "UNKNOWN");
        }
    }

    private void downloadPdf() {
        String eml = b.etEml.getText() == null ? "" : b.etEml.getText().toString().trim();
        if (eml.isEmpty()) return;
        Toast.makeText(this, "Generating evidence certificate…", Toast.LENGTH_SHORT).show();

        Map<String, String> body = new HashMap<>();
        body.put("rawEml", eml);
        CyberShieldApp.get().api().api().exportForensicsPdf(body).enqueue(new Callback<>() {
            @Override public void onResponse(Call<ResponseBody> call, Response<ResponseBody> resp) {
                if (resp.isSuccessful() && resp.body() != null) {
                    saveToDownloads(resp.body());
                } else {
                    Toast.makeText(ForensicsActivity.this, "PDF export failed (HTTP " + resp.code() + ")", Toast.LENGTH_LONG).show();
                }
            }
            @Override public void onFailure(Call<ResponseBody> call, Throwable t) {
                Toast.makeText(ForensicsActivity.this, "Could not reach backend: " + t.getMessage(), Toast.LENGTH_LONG).show();
            }
        });
    }

    private void saveToDownloads(ResponseBody body) {
        String filename = "cybershield-evidence-" + System.currentTimeMillis() + ".pdf";
        try {
            Uri uri;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                ContentValues values = new ContentValues();
                values.put(MediaStore.Downloads.DISPLAY_NAME, filename);
                values.put(MediaStore.Downloads.MIME_TYPE, "application/pdf");
                uri = getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values);
            } else {
                uri = null;
            }
            if (uri == null) {
                Toast.makeText(this, "Could not create download file.", Toast.LENGTH_SHORT).show();
                return;
            }
            try (OutputStream out = getContentResolver().openOutputStream(uri)) {
                if (out != null) out.write(body.bytes());
            }
            Toast.makeText(this, "Saved to Downloads: " + filename, Toast.LENGTH_LONG).show();
        } catch (IOException e) {
            Toast.makeText(this, "Failed to save PDF: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }
}
