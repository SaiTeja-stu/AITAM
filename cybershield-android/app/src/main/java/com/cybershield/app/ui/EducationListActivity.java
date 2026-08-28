package com.cybershield.app.ui;

import android.os.Bundle;
import android.view.View;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;

import com.cybershield.app.CyberShieldApp;
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
        CyberShieldApp.get().api().api().educationModules().enqueue(new Callback<>() {
            @Override public void onResponse(@NonNull Call<List<EduAdapter.Module>> c,
                                             @NonNull Response<List<EduAdapter.Module>> r) {
                List<EduAdapter.Module> mods = r.isSuccessful() ? r.body() : null;
                adapter.set(mods);
                boolean empty = mods == null || mods.isEmpty();
                b.empty.setText(empty ? "Couldn't load modules — is the backend reachable?" : "");
                b.empty.setVisibility(empty ? View.VISIBLE : View.GONE);
            }
            @Override public void onFailure(@NonNull Call<List<EduAdapter.Module>> c, @NonNull Throwable t) {
                b.empty.setText("Couldn't load modules — is the backend reachable?");
            }
        });
    }
}
