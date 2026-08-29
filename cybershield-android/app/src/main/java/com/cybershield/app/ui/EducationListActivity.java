package com.cybershield.app.ui;

import android.os.Bundle;
import android.view.View;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;

import com.cybershield.app.CyberShieldApp;
import com.cybershield.app.data.EducationCatalog;
import com.cybershield.app.data.SecureStore;
import com.cybershield.app.databinding.ActivityEducationListBinding;

import java.util.List;

import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

/** Awareness lessons, in English / Telugu / Hindi, with a read-aloud button on each. */
public class EducationListActivity extends AppCompatActivity {

    private ActivityEducationListBinding b;
    private EduAdapter adapter;
    private SecureStore store;

    @Override
    protected void onCreate(Bundle s) {
        super.onCreate(s);
        b = ActivityEducationListBinding.inflate(getLayoutInflater());
        setContentView(b.getRoot());
        store = CyberShieldApp.get().api().store();

        adapter = new EduAdapter(m -> startActivity(EduDetailActivity.intent(this, m, store.eduLang())));
        b.list.setLayoutManager(new LinearLayoutManager(this));
        b.list.setAdapter(adapter);

        switch (store.eduLang()) {
            case "te": b.langTe.setChecked(true); break;
            case "hi": b.langHi.setChecked(true); break;
            default:   b.langEn.setChecked(true);
        }
        b.langGroup.setOnCheckedStateChangeListener((g, ids) -> {
            int id = b.langGroup.getCheckedChipId();
            String lang = id == b.langTe.getId() ? "te" : id == b.langHi.getId() ? "hi" : "en";
            store.setEduLang(lang);
            load();
        });

        load();
    }

    private void load() {
        String lang = store.eduLang();
        List<EduAdapter.Module> mods = EducationCatalog.bundled(this, lang);
        adapter.set(mods);
        b.empty.setVisibility(mods.isEmpty() ? View.VISIBLE : View.GONE);
        if (mods.isEmpty()) b.empty.setText("Couldn't load lessons.");

        // English can also be refreshed from the backend; te/hi are bundled-only for now
        if ("en".equals(lang)) {
            CyberShieldApp.get().api().api().educationModules().enqueue(new Callback<>() {
                @Override public void onResponse(@NonNull Call<List<EduAdapter.Module>> c,
                                                 @NonNull Response<List<EduAdapter.Module>> r) {
                    if (r.isSuccessful() && r.body() != null && !r.body().isEmpty()
                            && "en".equals(store.eduLang())) {
                        adapter.set(r.body());
                        b.empty.setVisibility(View.GONE);
                    }
                }
                @Override public void onFailure(@NonNull Call<List<EduAdapter.Module>> c, @NonNull Throwable t) { }
            });
        }
    }
}
