package com.cybershield.app.ui;

import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;

import com.cybershield.app.CyberShieldApp;
import com.cybershield.app.databinding.ActivityForensicsBinding;
import com.cybershield.app.geo.LocationHelper;
import com.cybershield.app.net.dto.ForensicsResult;
import com.cybershield.app.net.dto.IncidentReportResponse;
import com.cybershield.app.net.dto.IncidentReportRequest;
import com.cybershield.app.net.PdfStreams;

import java.io.IOException;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

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
    private String analyzedEml;
    private String pendingPdfEml;
    private final ExecutorService pdfWorker = Executors.newSingleThreadExecutor();
    private final ActivityResultLauncher<String> createPdf = registerForActivityResult(
            new ActivityResultContracts.CreateDocument("application/pdf"), uri -> {
                if (uri != null && pendingPdfEml != null) exportPdf(uri, pendingPdfEml);
                else b.btnDownloadPdf.setEnabled(true);
                pendingPdfEml = null;
            });

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
        if (savedInstanceState != null) pendingPdfEml = savedInstanceState.getString("pendingPdfEml");
    }

    private void loadSample() {
        CyberShieldApp.get().api().api().forensicsSamples().enqueue(new Callback<>() {
            @Override public void onResponse(retrofit2.Call<List<Map<String, String>>> call,
                                              Response<List<Map<String, String>>> resp) {
                if (resp.isSuccessful() && resp.body() != null && !resp.body().isEmpty()) {
                    b.etEml.setText(resp.body().get(0).get("content"));
                } else {
                    showFailure("Could not load sample", "HTTP " + resp.code());
                }
            }
            @Override public void onFailure(retrofit2.Call<List<Map<String, String>>> call, Throwable t) {
                showFailure("Could not load sample", t.getMessage());
            }
        });
    }

    private void runAnalysis() {
        String eml = b.etEml.getText() == null ? "" : b.etEml.getText().toString();
        if (eml.trim().isEmpty()) {
            Toast.makeText(this, "Paste a raw .eml first, or load a sample.", Toast.LENGTH_SHORT).show();
            return;
        }
        b.progress.setVisibility(View.VISIBLE);
        b.resultBox.setVisibility(View.GONE);
        b.btnAnalyze.setEnabled(false);
        lastResult = null;
        analyzedEml = null;

        Map<String, String> body = new HashMap<>();
        body.put("rawEml", eml);
        CyberShieldApp.get().api().api().analyzeForensicsRaw(body).enqueue(new Callback<>() {
            @Override public void onResponse(Call<ForensicsResult> call, Response<ForensicsResult> resp) {
                b.progress.setVisibility(View.GONE);
                b.btnAnalyze.setEnabled(true);
                if (resp.isSuccessful() && resp.body() != null) {
                    lastResult = resp.body();
                    analyzedEml = eml;
                    render(lastResult);
                } else {
                    showFailure("Analysis failed", "HTTP " + resp.code());
                }
            }
            @Override public void onFailure(Call<ForensicsResult> call, Throwable t) {
                b.progress.setVisibility(View.GONE);
                b.btnAnalyze.setEnabled(true);
                showFailure("Analysis failed", t.getMessage());
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

        sb.append("\n── RELAY PATH & NETWORK GEOLOCATION ──\n");
        if (r.relayHops != null) {
            for (ForensicsResult.RelayHop hop : r.relayHops) {
                sb.append("Hop ").append(hop.hopNumber).append(": ").append(hop.ip);
                if (hop.geo != null) {
                    if (hop.geo.isPrivate) {
                        sb.append("  →  Private Network (RFC 1918 / LAN)");
                    } else if ("DEMO_FIXTURE".equals(hop.geo.lookupStatus)) {
                        sb.append("  →  ").append(hop.geo.city).append(", ").append(hop.geo.country)
                                .append(" [Demo Fixture]");
                    } else if (hop.geo.latitude != null && hop.geo.longitude != null) {
                        sb.append("  →  ").append(hop.geo.city).append(", ").append(hop.geo.country);
                    } else {
                        sb.append("  →  Location unavailable");
                    }
                    if (hop.geo.isp != null && !hop.geo.isp.isBlank()) {
                        sb.append("  (").append(hop.geo.isp).append(')');
                    }
                    if (hop.geo.isTorOrProxy) sb.append("  [TOR/PROXY]");
                    if (hop.geo.isDatacenter) sb.append("  [DATACENTER]");
                }
                if (hop.isOriginating) sb.append("  ★ Earliest Relay (Unverified sender boundary)");
                sb.append('\n');
            }
            sb.append("Note: Relay hops describe network infrastructure and do not establish verified sender physical location.\n");
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
            new AlertDialog.Builder(this)
                    .setTitle("Include device location?")
                    .setMessage("Device GPS is only used to suggest your nearest regional Cyber Crime Police Station for your draft report. It will not be submitted without your explicit action.")
                    .setPositiveButton("Continue", (d, w) -> LocationHelper.requestPermission(this, RC_LOCATION))
                    .setNegativeButton("Skip location", (d, w) -> submitIncident(null, null, null, "SKIPPED_BY_USER"))
                    .show();
            return;
        }
        LocationHelper.fetchCurrentLocation(this, new LocationHelper.Callback() {
            @Override public void onLocation(Double lat, Double lon, Float accuracyMeters, String provider) {
                submitIncident(lat, lon, accuracyMeters, provider);
            }
            @Override public void onUnavailable(String reason) {
                submitIncident(null, null, null, "UNAVAILABLE: " + reason);
            }
        });
    }

    private void submitIncident(Double lat, Double lon, Float accuracyMeters, String provider) {
        if (lastResult == null) return;
        b.btnReportForensic.setEnabled(false);
        IncidentReportRequest request = new IncidentReportRequest(lastResult.evidenceSha256,
                lastResult.subject, lastResult.fromAddress, lastResult.riskTier, lastResult.overallRiskScore,
                lat, lon, accuracyMeters, provider, "Prepared from Secure Me Android email analysis");
        CyberShieldApp.get().api().api().reportIncident(request).enqueue(new Callback<>() {
                    @Override public void onResponse(Call<IncidentReportResponse> call, Response<IncidentReportResponse> response) {
                        b.btnReportForensic.setEnabled(true);
                        if (!response.isSuccessful() || response.body() == null) {
                            showFailure("Incident preparation failed", "HTTP " + response.code());
                            return;
                        }
                        IncidentReportResponse resp = response.body();
                        new AlertDialog.Builder(ForensicsActivity.this)
                                .setTitle("Incident details prepared")
                                .setMessage("Reference: " + resp.incidentId
                                        + "\nJurisdiction: " + resp.jurisdictionStation
                                        + "\nHelpline: " + resp.helpline
                                        + "\n\nThis app has not submitted a police complaint. Save the report and submit it through the official cybercrime portal.")
                                .setPositiveButton("OK", null)
                                .show();
                    }
                    @Override public void onFailure(Call<IncidentReportResponse> call, Throwable error) {
                        b.btnReportForensic.setEnabled(true);
                        showFailure("Incident preparation failed", error.getMessage());
                    }
                });
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == RC_LOCATION) {
            boolean granted = LocationHelper.hasPermission(this);
            if (granted) lodgeIncident();
            else submitIncident(null, null, null, "PERMISSION_DENIED");
        }
    }

    private void downloadPdf() {
        if (analyzedEml == null) return;
        pendingPdfEml = analyzedEml;
        b.btnDownloadPdf.setEnabled(false);
        createPdf.launch("secureme-forensic-report-" + System.currentTimeMillis() + ".pdf");
    }

    private void showFailure(String title, String detail) {
        if (isFinishing() || isDestroyed()) return;
        new AlertDialog.Builder(this).setTitle(title)
                .setMessage((detail == null ? "The request could not be completed." : detail)
                        + "\n\nServer: " + CyberShieldApp.get().api().store().baseUrl()
                        + "\nCheck the connection and the Server setting on the sign-in screen. If the server is starting, retry shortly.")
                .setPositiveButton("OK", null).show();
    }

    private void exportPdf(Uri uri, String eml) {
        Toast.makeText(this, "Generating forensic report…", Toast.LENGTH_SHORT).show();
        Map<String, String> body = new HashMap<>();
        body.put("rawEml", eml);
        pdfWorker.execute(() -> {
            String message;
            try {
                Response<ResponseBody> response = CyberShieldApp.get().api().api().exportForensicsPdf(body).execute();
                if (!response.isSuccessful() || response.body() == null) {
                    if (response.errorBody() != null) response.errorBody().close();
                    throw new IOException("PDF export failed (HTTP " + response.code() + ")");
                }
                try (ResponseBody pdf = response.body();
                     OutputStream out = getContentResolver().openOutputStream(uri, "w")) {
                    if (out == null) throw new IOException("Could not open the selected file");
                    PdfStreams.copy(pdf.byteStream(), out);
                }
                message = "Forensic report saved to the selected location.";
            } catch (IOException | RuntimeException e) {
                try { android.provider.DocumentsContract.deleteDocument(getContentResolver(), uri); }
                catch (Exception ignored) { /* Provider may not support deleting partial files. */ }
                message = "Could not save report: " + e.getMessage();
            }
            String resultMessage = message;
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed()) return;
                b.btnDownloadPdf.setEnabled(true);
                Toast.makeText(this, resultMessage, Toast.LENGTH_LONG).show();
            });
        });
    }

    @Override protected void onSaveInstanceState(Bundle state) {
        super.onSaveInstanceState(state);
        state.putString("pendingPdfEml", pendingPdfEml);
    }

    @Override protected void onDestroy() {
        pdfWorker.shutdown();
        super.onDestroy();
    }
}
