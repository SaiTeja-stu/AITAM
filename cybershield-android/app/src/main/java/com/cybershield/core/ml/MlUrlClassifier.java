package com.cybershield.core.ml;

import android.content.Context;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * On-device twin of the backend {@code MlUrlClassifier}: loads
 * {@code assets/ml/url_model.json} and scores a URL's lexical phishing
 * probability. Standardised LogisticRegression over
 * {@link UrlFeatureExtractor#FEATURES}. Inert (probability -1) if the asset is
 * missing or its feature list doesn't match the code.
 */
public final class MlUrlClassifier {

    private final boolean ready;
    private final double[] mean;
    private final double[] scale;
    private final double[] coef;
    private final double intercept;
    private final double urlLenP99;
    private final double urlEntropyP99;
    private final double hostEntropyP99;

    public MlUrlClassifier(Context ctx) {
        boolean ok = false;
        double[] mn = null, sc = null, cf = null;
        double ic = 0, ul = Double.MAX_VALUE, ue = Double.MAX_VALUE, he = Double.MAX_VALUE;
        try (Reader r = new InputStreamReader(
                ctx.getApplicationContext().getAssets().open("ml/url_model.json"), StandardCharsets.UTF_8)) {
            JsonObject m = JsonParser.parseReader(r).getAsJsonObject();
            JsonArray names = m.getAsJsonArray("features");
            String[] want = UrlFeatureExtractor.FEATURES;
            if (names.size() == want.length) {
                boolean order = true;
                for (int i = 0; i < want.length; i++) {
                    if (!want[i].equals(names.get(i).getAsString())) { order = false; break; }
                }
                if (order) {
                    mn = arr(m.getAsJsonArray("mean"));
                    sc = arr(m.getAsJsonArray("scale"));
                    cf = arr(m.getAsJsonArray("coef"));
                    ic = m.get("intercept").getAsDouble();
                    JsonObject b = m.getAsJsonObject("baseline");
                    if (b != null) {
                        ul = opt(b, "url_length_p99", ul);
                        ue = opt(b, "url_entropy_p99", ue);
                        he = opt(b, "host_entropy_p99", he);
                    }
                    ok = mn.length == want.length && sc.length == want.length && cf.length == want.length;
                }
            }
        } catch (Exception ignored) {
            // asset missing / malformed -> classifier stays inert
        }
        this.ready = ok;
        this.mean = mn;
        this.scale = sc;
        this.coef = cf;
        this.intercept = ic;
        this.urlLenP99 = ul;
        this.urlEntropyP99 = ue;
        this.hostEntropyP99 = he;
    }

    public boolean isReady() {
        return ready;
    }

    /** Probability in [0,1] that the URL is phishing/scam by its lexical shape; -1 if inert. */
    public double probability(String url) {
        if (!ready) return -1;
        double[] v = UrlFeatureExtractor.vector(url);
        double z = intercept;
        for (int i = 0; i < v.length; i++) {
            double s = scale[i] == 0 ? 1 : scale[i];
            z += coef[i] * ((v[i] - mean[i]) / s);
        }
        return 1.0 / (1.0 + Math.exp(-z));
    }

    public String anomalyNote(String url) {
        if (!ready) return "";
        Map<String, Double> f = UrlFeatureExtractor.extract(url);
        java.util.List<String> notes = new java.util.ArrayList<>();
        if (f.get("url_length") > urlLenP99 * 2) notes.add("unusually long");
        if (f.get("host_entropy") > hostEntropyP99 + 0.6) notes.add("high-randomness hostname");
        if (f.get("url_entropy") > urlEntropyP99 + 0.6) notes.add("high-randomness URL");
        return String.join(", ", notes);
    }

    private static double[] arr(JsonArray a) {
        double[] out = new double[a.size()];
        for (int i = 0; i < out.length; i++) out[i] = a.get(i).getAsDouble();
        return out;
    }

    private static double opt(JsonObject o, String k, double dflt) {
        return o.has(k) ? o.get(k).getAsDouble() : dflt;
    }
}
