package com.cybershield.app.ui;

import android.os.Bundle;
import android.view.View;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;

import com.cybershield.app.CyberShieldApp;
import com.cybershield.app.data.EducationCatalog;
import com.cybershield.app.databinding.ActivityEducationListBinding;

import java.util.List;

import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

/** Full catalogue of awareness modules; taps open {@link EduDetailActivity}. */
public class EducationListActivity extends AppCompatActivity {

    private ActivityEducationListBinding b;
    private EduAdapter adapter;

    @Override
    protected void onCreate(Bundle s) {
        super.onCreate(s);
        b = ActivityEducationListBinding.inflate(getLayoutInflater());
        setContentView(b.getRoot());

        adapter = new EduAdapter(m -> startActivity(EduDetailActivity.intent(this, m)));
        b.list.setLayoutManager(new LinearLayoutManager(this));
        b.list.setAdapter(adapter);

        load();
    }

    private void load() {
        // Bundled copy first so the screen is never empty, then let the backend refresh it.
        showOffline();
        CyberShieldApp.get().api().api().educationModules().enqueue(new Callback<>() {
            @Override public void onResponse(@NonNull Call<List<EduAdapter.Module>> c,
                                             @NonNull Response<List<EduAdapter.Module>> r) {
                if (r.isSuccessful() && r.body() != null && !r.body().isEmpty()) {
                    adapter.set(r.body());
                    b.empty.setVisibility(View.GONE);
                }
            }
            @Override public void onFailure(@NonNull Call<List<EduAdapter.Module>> c, @NonNull Throwable t) {
                showOffline();
            }
        });
    }

    private void showOffline() {
        List<EduAdapter.Module> mods = EducationCatalog.bundled(this);
        adapter.set(mods);
        b.empty.setVisibility(mods.isEmpty() ? View.VISIBLE : View.GONE);
        if (mods.isEmpty()) b.empty.setText("No modules available.");
    }
}
