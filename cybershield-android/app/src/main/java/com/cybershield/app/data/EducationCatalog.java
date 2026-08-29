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

/** Offline copy of the awareness modules, bundled in assets, in English / Telugu / Hindi. */
public final class EducationCatalog {

    public static final String[] LANGS = {"en", "te", "hi"};
    public static final String[] LANG_LABELS = {"English", "తెలుగు", "हिन्दी"};

    private EducationCatalog() {}

    public static String label(String lang) {
        for (int i = 0; i < LANGS.length; i++) if (LANGS[i].equals(lang)) return LANG_LABELS[i];
        return "English";
    }

    /** BCP-47 tag for TextToSpeech. */
    public static String bcp47(String lang) {
        switch (lang == null ? "en" : lang) {
            case "te": return "te-IN";
            case "hi": return "hi-IN";
            default:   return "en-IN";
        }
    }

    public static List<EduAdapter.Module> bundled(Context ctx, String lang) {
        String file = "en".equals(lang) || lang == null
                ? "education/modules.json" : "education/modules_" + lang + ".json";
        List<EduAdapter.Module> m = read(ctx, file);
        if (m.isEmpty() && !file.equals("education/modules.json")) {
            m = read(ctx, "education/modules.json");   // fall back to English
        }
        return m;
    }

    private static List<EduAdapter.Module> read(Context ctx, String assetPath) {
        try (Reader r = new InputStreamReader(ctx.getAssets().open(assetPath), StandardCharsets.UTF_8)) {
            EduAdapter.Module[] mods = new Gson().fromJson(r, EduAdapter.Module[].class);
            return mods == null ? new ArrayList<>() : Arrays.asList(mods);
        } catch (Exception e) {
            return new ArrayList<>();
        }
    }
}
