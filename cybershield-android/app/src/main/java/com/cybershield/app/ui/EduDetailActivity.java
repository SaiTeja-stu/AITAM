package com.cybershield.app.ui;

import android.content.Context;
import android.content.Intent;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.speech.tts.TextToSpeech;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.cybershield.app.CyberShieldApp;
import com.cybershield.app.data.EducationCatalog;
import com.google.android.material.chip.Chip;
import com.google.android.material.chip.ChipGroup;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * One lesson — understood by SEEING (big icon, one rule, colour-coded ✓ / ✗
 * lists in large type) and by HEARING (a Listen button reads it aloud, slowly,
 * in the chosen language). English / తెలుగు / हिन्दी switch on this screen.
 */
public class EduDetailActivity extends AppCompatActivity {

    private TextToSpeech tts;
    private boolean ttsReady = false;
    private String speech = "";
    private String moduleId;
    private String lang = "en";

    private Button listenBtn;
    private LinearLayout body;
    private ScrollView scroll;

    public static Intent intent(Context ctx, EduAdapter.Module m, String lang) {
        Intent i = new Intent(ctx, EduDetailActivity.class);
        i.putExtra("id", m.id);
        i.putExtra("lang", lang);
        return i;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        moduleId = getIntent().getStringExtra("id");
        lang = or(getIntent().getStringExtra("lang"), CyberShieldApp.get().api().store().eduLang());

        int pad = dp(20);
        LinearLayout outer = new LinearLayout(this);
        outer.setOrientation(LinearLayout.VERTICAL);
        outer.setBackgroundResource(com.cybershield.app.R.drawable.bg_gradient);
        outer.setPadding(pad, pad, pad, 0);

        // language switch
        ChipGroup cg = new ChipGroup(this);
        cg.setSingleSelection(true);
        cg.setSelectionRequired(true);
        String[] labels = EducationCatalog.LANG_LABELS;
        for (int k = 0; k < EducationCatalog.LANGS.length; k++) {
            Chip c = new Chip(this);
            c.setText(labels[k]);
            c.setCheckable(true);
            c.setTag(EducationCatalog.LANGS[k]);
            c.setChecked(EducationCatalog.LANGS[k].equals(lang));
            cg.addView(c);
        }
        cg.setOnCheckedStateChangeListener((g, ids) -> {
            int id = cg.getCheckedChipId();
            if (id == View.NO_ID) return;
            Object tag = cg.findViewById(id).getTag();
            String newLang = tag == null ? "en" : tag.toString();
            if (newLang.equals(lang)) return;
            lang = newLang;
            CyberShieldApp.get().api().store().setEduLang(lang);
            render();
            initTts();
        });
        outer.addView(cg);

        body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(0, dp(6), 0, dp(36));
        scroll = new ScrollView(this);
        scroll.addView(body);
        LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f);
        scroll.setLayoutParams(sp);
        outer.addView(scroll);

        setContentView(outer);

        render();
        initTts();
    }

    private EduAdapter.Module module() {
        for (EduAdapter.Module m : EducationCatalog.bundled(this, lang)) {
            if (m.id != null && m.id.equals(moduleId)) return m;
        }
        // fall back to English
        for (EduAdapter.Module m : EducationCatalog.bundled(this, "en")) {
            if (m.id != null && m.id.equals(moduleId)) return m;
        }
        return null;
    }

    private void render() {
        body.removeAllViews();
        EduAdapter.Module m = module();
        if (m == null) { finish(); return; }

        String title = or(m.title, "");
        String rule = or(m.rule, "");
        String summary = or(m.summary, "");
        List<String> doThis = m.safeActions();
        List<String> redFlags = m.redFlags == null ? new ArrayList<>() : m.redFlags;

        ImageView ic = new ImageView(this);
        ic.setImageResource(EduAdapter.iconFor(moduleId));
        LinearLayout.LayoutParams icp = new LinearLayout.LayoutParams(dp(72), dp(72));
        icp.gravity = Gravity.CENTER_HORIZONTAL;
        icp.topMargin = dp(6);
        ic.setLayoutParams(icp);
        body.addView(ic);

        body.addView(centre(title, 24, true, com.cybershield.app.R.color.text));

        listenBtn = new Button(this);
        listenBtn.setText("▶  " + s(lang, "Listen", "వినండి", "सुनें"));
        listenBtn.setTextSize(18);
        listenBtn.setAllCaps(false);
        listenBtn.setBackgroundTintList(getColorStateList(com.cybershield.app.R.color.sky));
        listenBtn.setTextColor(getColor(com.cybershield.app.R.color.ink));
        listenBtn.setEnabled(ttsReady);
        LinearLayout.LayoutParams lbp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lbp.topMargin = dp(12);
        listenBtn.setLayoutParams(lbp);
        listenBtn.setOnClickListener(v -> toggleSpeak());
        body.addView(listenBtn);

        if (!rule.isEmpty()) {
            TextView box = new TextView(this);
            box.setText(rule);
            box.setTextSize(19);
            box.setTypeface(Typeface.DEFAULT_BOLD);
            box.setTextColor(getColor(com.cybershield.app.R.color.text));
            box.setPadding(dp(16), dp(16), dp(16), dp(16));
            GradientDrawable bg = new GradientDrawable();
            bg.setColor(0xFF10233A);
            bg.setStroke(dp(2), getColor(com.cybershield.app.R.color.sky));
            bg.setCornerRadius(dp(12));
            box.setBackground(bg);
            LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
            bp.topMargin = dp(16);
            box.setLayoutParams(bp);
            body.addView(box);
        }
        if (!summary.isEmpty()) {
            TextView sv = new TextView(this);
            sv.setText(summary);
            sv.setTextSize(16);
            sv.setTextColor(getColor(com.cybershield.app.R.color.muted));
            sv.setPadding(0, dp(14), 0, dp(2));
            body.addView(sv);
        }

        body.addView(heading(s(lang, "DO THIS", "ఇలా చేయండి", "यह करें"), com.cybershield.app.R.color.risk_safe));
        for (String d : doThis) body.addView(pointLine("✓  ", d, com.cybershield.app.R.color.risk_safe));
        body.addView(heading(s(lang, "DANGER SIGNS", "ప్రమాద సంకేతాలు", "ख़तरे के संकेत"), com.cybershield.app.R.color.risk_malicious));
        for (String f : redFlags) body.addView(pointLine("✗  ", f, com.cybershield.app.R.color.risk_malicious));

        speech = buildSpeech(title, rule, doThis, redFlags);
        scroll.scrollTo(0, 0);
    }

    // ---- text-to-speech --------------------------------------------

    private void initTts() {
        if (tts != null) { tts.stop(); tts.shutdown(); tts = null; }
        ttsReady = false;
        if (listenBtn != null) listenBtn.setEnabled(false);
        final String want = lang;
        tts = new TextToSpeech(this, status -> {
            if (status != TextToSpeech.SUCCESS) return;
            int r = tts.setLanguage(Locale.forLanguageTag(EducationCatalog.bcp47(want)));
            boolean ok = r != TextToSpeech.LANG_MISSING_DATA && r != TextToSpeech.LANG_NOT_SUPPORTED;
            if (!ok) tts.setLanguage(Locale.US);
            tts.setSpeechRate(0.85f);
            tts.setPitch(1.0f);
            ttsReady = true;
            final boolean fellBack = !ok && !"en".equals(want);
            runOnUiThread(() -> {
                if (listenBtn != null) {
                    listenBtn.setEnabled(true);
                    if (fellBack) listenBtn.setText("▶  Listen (English voice)");
                }
                if (fellBack) Toast.makeText(this,
                        "Voice for this language isn't installed — Settings › Languages › Text-to-speech.",
                        Toast.LENGTH_LONG).show();
            });
        });
    }

    private void toggleSpeak() {
        if (!ttsReady) return;
        if (tts.isSpeaking()) {
            tts.stop();
            listenBtn.setText("▶  " + s(lang, "Listen", "వినండి", "सुनें"));
        } else {
            tts.speak(speech, TextToSpeech.QUEUE_FLUSH, null, "edu");
            listenBtn.setText("■  " + s(lang, "Stop", "ఆపండి", "रोकें"));
        }
    }

    private String buildSpeech(String title, String rule, List<String> doThis, List<String> flags) {
        StringBuilder sb = new StringBuilder(title).append(". ");
        if (!rule.isEmpty()) sb.append(rule).append(". ");
        if (!doThis.isEmpty()) {
            sb.append(s(lang, "What to do", "ఏం చేయాలి", "क्या करें")).append(". ");
            for (String d : doThis) sb.append(d).append(". ");
        }
        if (!flags.isEmpty()) {
            sb.append(s(lang, "Danger signs", "ప్రమాద సంకేతాలు", "ख़तरे के संकेत")).append(". ");
            for (String f : flags) sb.append(f.replace("\"", "")).append(". ");
        }
        return sb.toString();
    }

    @Override
    protected void onDestroy() {
        if (tts != null) { tts.stop(); tts.shutdown(); }
        super.onDestroy();
    }

    // ---- helpers --------------------------------------------------

    private static String s(String lang, String en, String te, String hi) {
        return "te".equals(lang) ? te : "hi".equals(lang) ? hi : en;
    }

    private TextView centre(String txt, int sizeSp, boolean bold, int colorRes) {
        TextView t = new TextView(this);
        t.setText(txt);
        t.setTextSize(sizeSp);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        t.setTextColor(getColor(colorRes));
        t.setGravity(Gravity.CENTER_HORIZONTAL);
        t.setPadding(0, dp(10), 0, dp(4));
        return t;
    }

    private TextView heading(String txt, int colorRes) {
        TextView t = new TextView(this);
        t.setText(txt);
        t.setTextSize(18);
        t.setTypeface(Typeface.DEFAULT_BOLD);
        t.setTextColor(getColor(colorRes));
        t.setPadding(0, dp(22), 0, dp(8));
        return t;
    }

    private View pointLine(String mark, String txt, int colorRes) {
        TextView t = new TextView(this);
        android.text.SpannableString ss = new android.text.SpannableString(mark + txt);
        ss.setSpan(new android.text.style.ForegroundColorSpan(getColor(colorRes)), 0, mark.length(), 0);
        t.setText(ss);
        t.setTextSize(17);
        t.setLineSpacing(dp(3), 1f);
        t.setTextColor(getColor(com.cybershield.app.R.color.text));
        t.setPadding(dp(2), dp(7), 0, dp(7));
        return t;
    }

    private int dp(int v) { return Math.round(v * getResources().getDisplayMetrics().density); }

    private static String or(String x, String dflt) { return x == null || x.isEmpty() ? dflt : x; }
}
