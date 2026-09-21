package com.cybershield.app.data;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import com.cybershield.app.CyberShieldApp;
import com.cybershield.app.engine.LocalFraudEngine;
import com.cybershield.app.engine.LocalVerdict;
import com.cybershield.app.engine.UpiUri;
import com.cybershield.app.net.dto.AnalyzeRequest;
import com.cybershield.app.net.dto.AnalyzeResponse;
import com.cybershield.app.net.dto.IncidentReportRequest;
import com.cybershield.app.net.dto.IncidentReportResponse;
import com.cybershield.app.net.dto.ReportRequest;
import com.cybershield.app.util.Redact;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import retrofit2.Call;

/**
 * One entry point for analysis. Strategy:
 *   1. run the on-device engine immediately (fast, offline, private)
 *   2. call the backend for the authoritative verdict
 *   3. persist a redacted history row
 * Callers get the local verdict synchronously and the server verdict via callback.
 */
public class Repository {

    public interface Callback {
        void onLocal(LocalVerdict local);
        void onServer(AnalyzeResponse server);
        void onServerError(String message);
    }

    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());
    private final LocalFraudEngine engine;
    private final AppDatabase db;

    public Repository(Context ctx) {
        this.engine = new LocalFraudEngine(ctx);
        this.db = CyberShieldApp.get().db();
    }

    public void analyze(String type, String content, String source, Callback cb) {
        // 1. instant heuristic pre-check (keeps the UI responsive)
        LocalVerdict local = localCheck(type, content);
        cb.onLocal(local);

        io.execute(() -> {
            // 2. full on-device analysis — the 22-policy engine, no network needed
            AnalyzeResponse verdict;
            try {
                verdict = CyberShieldApp.get().analyzer().analyze(type, content, null);
            } catch (Throwable t) {
                main.post(() -> cb.onServerError("On-device analysis failed"));
                return;
            }
            persist(verdict, content);
            final AnalyzeResponse onDevice = verdict;
            main.post(() -> cb.onServer(onDevice));

            // 3. optional: let a configured backend refine the verdict (admin sync,
            //    live feeds, LLM prose). Silent if unreachable — the on-device
            //    result already stands.
            if (!CyberShieldApp.get().api().store().hasSession()) return;
            try {
                Call<AnalyzeResponse> call = CyberShieldApp.get().api().api()
                        .analyze(new AnalyzeRequest(type, content, source));
                retrofit2.Response<AnalyzeResponse> resp = call.execute();
                if (resp.isSuccessful() && resp.body() != null) {
                    AnalyzeResponse server = resp.body();
                    persist(server, content);
                    main.post(() -> cb.onServer(server));
                }
            } catch (Exception ignored) {
                // offline / no backend — on-device verdict is authoritative
            }
        });
    }

    public void report(String type, String content, String note) {
        io.execute(() -> {
            try {
                CyberShieldApp.get().api().api()
                        .report(new ReportRequest(type, content, note)).execute();
            } catch (Exception ignored) {
            }
        });
    }

    public interface IncidentCallback {
        void onLodged(IncidentReportResponse response);
        void onFailed(String message);
    }

    /**
     * Lodges a geo-tagged incident report with the forensic backend, which
     * routes it to the nearest Cyber Crime Police Station jurisdiction based
     * on the GPS coordinates captured via {@link com.cybershield.app.geo.LocationHelper}.
     * Pass (0,0) for lat/lon when a GPS fix could not be obtained.
     */
    public void reportIncident(String type, String content, String riskTier, int riskScore,
                                double userLat, double userLon, float accuracyMeters,
                                String networkProvider, IncidentCallback cb) {
        io.execute(() -> {
            try {
                String evidenceSha256 = sha256(content);
                IncidentReportRequest req = new IncidentReportRequest(
                        evidenceSha256, type, content, riskTier, riskScore,
                        userLat, userLon, accuracyMeters, networkProvider,
                        "Reported from Secure Me Android app");
                retrofit2.Response<IncidentReportResponse> resp =
                        CyberShieldApp.get().api().api().reportIncident(req).execute();
                if (resp.isSuccessful() && resp.body() != null) {
                    IncidentReportResponse body = resp.body();
                    main.post(() -> cb.onLodged(body));
                } else {
                    main.post(() -> cb.onFailed("Server rejected the incident report"));
                }
            } catch (Exception e) {
                main.post(() -> cb.onFailed("Could not reach the server — check your connection"));
            }
        });
    }

    private static String sha256(String content) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(content == null ? new byte[0] : content.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "sha256-error";
        }
    }

    private LocalVerdict localCheck(String type, String content) {
        switch (type) {
            case "QR": {
                UpiUri upi = UpiUri.parse(content);
                return engine.checkPayment(upi.valid ? upi : null, content);
            }
            case "URL":
                return engine.checkUrl(content);
            default:
                return engine.checkText(content);
        }
    }

    private void persist(AnalyzeResponse r, String content) {
        try {
            ScanEntity e = new ScanEntity();
            e.id = r.reportId != null ? r.reportId : UUID.randomUUID().toString();
            e.type = r.contentType;
            e.snippet = Redact.snippet(content);
            e.riskScore = r.riskScore;
            e.riskLevel = r.riskLevel;
            e.priority = r.priority;
            e.serverChecked = true;
            e.createdAt = System.currentTimeMillis();
            db.scanDao().insert(e);
        } catch (Exception ignored) {
        }
    }

}
