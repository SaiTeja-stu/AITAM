package com.cybershield.app.ui;

import android.annotation.SuppressLint;
import android.os.Bundle;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.camera.core.CameraSelector;
import androidx.camera.core.ImageAnalysis;
import androidx.camera.core.Preview;
import androidx.camera.lifecycle.ProcessCameraProvider;
import androidx.core.content.ContextCompat;

import com.cybershield.app.databinding.ActivityScanQrBinding;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.mlkit.vision.barcode.BarcodeScanner;
import com.google.mlkit.vision.barcode.BarcodeScannerOptions;
import com.google.mlkit.vision.barcode.BarcodeScanning;
import com.google.mlkit.vision.barcode.common.Barcode;
import com.google.mlkit.vision.common.InputImage;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * CameraX preview + ML Kit barcode scanning, fully on-device. The decoded
 * payload is routed to the verdict screen; the camera never uploads anything.
 */
public class ScanQrActivity extends AppCompatActivity {

    private ActivityScanQrBinding b;
    private ExecutorService analysisExecutor;
    private BarcodeScanner scanner;
    private boolean handled = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        b = ActivityScanQrBinding.inflate(getLayoutInflater());
        setContentView(b.getRoot());

        analysisExecutor = Executors.newSingleThreadExecutor();
        scanner = BarcodeScanning.getClient(new BarcodeScannerOptions.Builder()
                .setBarcodeFormats(Barcode.FORMAT_QR_CODE, Barcode.FORMAT_DATA_MATRIX)
                .build());

        ListenableFuture<ProcessCameraProvider> future = ProcessCameraProvider.getInstance(this);
        future.addListener(() -> {
            try {
                bind(future.get());
            } catch (Exception e) {
                Log.e("ScanQr", "camera bind failed", e);
                finish();
            }
        }, ContextCompat.getMainExecutor(this));
    }

    @SuppressLint("UnsafeOptInUsageError")
    private void bind(ProcessCameraProvider provider) {
        Preview preview = new Preview.Builder().build();
        preview.setSurfaceProvider(b.preview.getSurfaceProvider());

        ImageAnalysis analysis = new ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build();
        analysis.setAnalyzer(analysisExecutor, image -> {
            if (handled || image.getImage() == null) { image.close(); return; }
            InputImage input = InputImage.fromMediaImage(
                    image.getImage(), image.getImageInfo().getRotationDegrees());
            scanner.process(input)
                    .addOnSuccessListener(barcodes -> {
                        for (Barcode code : barcodes) {
                            String raw = code.getRawValue();
                            if (raw != null && !raw.isEmpty() && !handled) {
                                handled = true;
                                onPayload(raw);
                                return;
                            }
                        }
                    })
                    .addOnCompleteListener(t -> image.close());
        });

        provider.unbindAll();
        provider.bindToLifecycle(this, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis);
    }

    private void onPayload(@NonNull String raw) {
        runOnUiThread(() -> {
            b.status.setText("Checking…");
            String type = raw.toLowerCase().startsWith("upi://") || raw.startsWith("http") ? "QR" : "QR";
            VerdictActivity.start(this, "QR", raw, "qr-scan");
            finish();
        });
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (analysisExecutor != null) analysisExecutor.shutdown();
        if (scanner != null) scanner.close();
    }
}
