package com.cybershield.analyze.ml;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.InputStream;

/**
 * Loads {@code ml/url_model.json} (trained by {@code ml/train_url_model.py}) and
 * scores a URL's <b>lexical</b> phishing probability.
 *
 * <p>Model = standardised LogisticRegression on {@link UrlFeatureExtractor#FEATURES}.
 * The output is a probability in [0,1] and is consumed as ONE capped signal by
 * {@code MlUrlScorePolicy} — it never decides a verdict by itself. If the model
 * file is missing or unreadable the classifier is simply inert (fails open).
 */
@Component
public class MlUrlClassifier {

    private static final Logger log = LoggerFactory.getLogger(MlUrlClassifier.class);

    private final boolean ready;
    private final double[] mean;
    private final double[] scale;
    private final double[] coef;
    private final double intercept;
    private final double urlLenP99;
    private final double urlEntropyP99;
    private final double hostEntropyP99;
    private final String trainedAt;
    private final double auc;

    public MlUrlClassifier(ObjectMapper mapper) {
        boolean ok = false;
        double[] mn = null, sc = null, cf = null;
        double ic = 0, ul = 0, ue = 0, he = 0, a = 0;
        String ts = "n/a";
        try (InputStream in = new ClassPathResource("ml/url_model.json").getInputStream()) {
            JsonNode m = mapper.readTree(in);
            JsonNode names = m.get("features");
            String[] want = UrlFeatureExtractor.FEATURES;
            if (names == null || names.size() != want.length) {
                throw new IllegalStateException("feature list mismatch (model " +
                        (names == null ? 0 : names.size()) + " vs code " + want.length + ")");
            }
            for (int i = 0; i < want.length; i++) {
                if (!want[i].equals(names.get(i).asText())) {
                    throw new IllegalStateException("feature order mismatch at " + i + ": model=" +
                            names.get(i).asText() + " code=" + want[i]);
                }
            }
            mn = toArray(m.get("mean"));
            sc = toArray(m.get("scale"));
            cf = toArray(m.get("coef"));
            ic = m.get("intercept").asDouble();
            JsonNode b = m.path("baseline");
            ul = b.path("url_length_p99").asDouble(Double.MAX_VALUE);
            ue = b.path("url_entropy_p99").asDouble(Double.MAX_VALUE);
            he = b.path("host_entropy_p99").asDouble(Double.MAX_VALUE);
            a = m.path("metrics").path("roc_auc").asDouble(0);
            ts = m.path("trained_at").asText("n/a");
            ok = mn.length == want.length && sc.length == want.length && cf.length == want.length;
        } catch (Exception e) {
            log.warn("URL ML model not loaded ({}), classifier is inert", e.toString());
        }
        this.ready = ok;
        this.mean = mn;
        this.scale = sc;
        this.coef = cf;
        this.intercept = ic;
        this.urlLenP99 = ul;
        this.urlEntropyP99 = ue;
        this.hostEntropyP99 = he;
        this.trainedAt = ts;
        this.auc = a;
        if (ok) log.info("URL ML model loaded (trained {}, held-out AUC {})", ts, auc);
    }

    public boolean isReady() {
        return ready;
    }

    /** Probability in [0,1] that the URL is phishing/scam by its lexical shape. -1 if inert. */
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

    /** Short human note when the URL is structurally far outside the "normal" baseline, else "". */
    public String anomalyNote(String url) {
        if (!ready) return "";
        var f = UrlFeatureExtractor.extract(url);
        java.util.List<String> notes = new java.util.ArrayList<>();
        if (f.get("url_length") > urlLenP99 * 2) notes.add("unusually long");
        if (f.get("host_entropy") > hostEntropyP99 + 0.6) notes.add("high-randomness hostname");
        if (f.get("url_entropy") > urlEntropyP99 + 0.6) notes.add("high-randomness URL");
        return String.join(", ", notes);
    }

    public String trainedAt() {
        return trainedAt;
    }

    private static double[] toArray(JsonNode n) {
        double[] a = new double[n.size()];
        for (int i = 0; i < a.length; i++) a[i] = n.get(i).asDouble();
        return a;
    }
}
