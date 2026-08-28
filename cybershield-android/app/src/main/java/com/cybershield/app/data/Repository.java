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
import com.cybershield.app.net.dto.ReportRequest;
import com.cybershield.app.util.Redact;

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
        // 1. on-device
        LocalVerdict local = localCheck(type, content);
        cb.onLocal(local);

        // 2. server
        io.execute(() -> {
            try {
                Call<AnalyzeResponse> call = CyberShieldApp.get().api().api()
                        .analyze(new AnalyzeRequest(type, content, source));
                retrofit2.Response<AnalyzeResponse> resp = call.execute();
                if (resp.isSuccessful() && resp.body() != null) {
                    AnalyzeResponse server = resp.body();
                    persist(server, content);
                    main.post(() -> cb.onServer(server));
                } else {
                    main.post(() -> cb.onServerError("Server returned " + resp.code()));
                }
            } catch (Exception e) {
                persistLocalOnly(local, type, content);
                main.post(() -> cb.onServerError("Offline — showing on-device check only"));
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

    private void persistLocalOnly(LocalVerdict v, String type, String content) {
        try {
            ScanEntity e = new ScanEntity();
            e.id = UUID.randomUUID().toString();
            e.type = type;
            e.snippet = Redact.snippet(content);
            e.riskScore = v.score;
            e.riskLevel = v.level.name();
            e.priority = v.priority();
            e.serverChecked = false;
            e.createdAt = System.currentTimeMillis();
            db.scanDao().insert(e);
        } catch (Exception ignored) {
        }
    }
}
