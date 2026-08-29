package com.cybershield.app.data;

import android.content.Context;

import com.cybershield.app.ui.EduAdapter;
import com.google.gson.Gson;

import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Offline copy of the awareness modules, bundled in assets. Used when no backend is reachable. */
public final class EducationCatalog {

    private EducationCatalog() {}

    public static List<EduAdapter.Module> bundled(Context ctx) {
        try (Reader r = new InputStreamReader(
                ctx.getAssets().open("education/modules.json"), StandardCharsets.UTF_8)) {
            EduAdapter.Module[] mods = new Gson().fromJson(r, EduAdapter.Module[].class);
            return mods == null ? new ArrayList<>() : Arrays.asList(mods);
        } catch (Exception e) {
            return new ArrayList<>();
        }
    }
}
