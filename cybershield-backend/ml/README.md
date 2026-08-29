# URL risk model

A small, interpretable model that scores a URL's **lexical** phishing likelihood.
Its output is fed into the rule-based risk engine as **one capped signal** (`URL-13`,
max +18, never CRITICAL) — it never decides a verdict alone.

## Files

| file | purpose |
|---|---|
| `url_features.py` | the 24 lexical features — **source of truth**. Mirrored in `UrlFeatureExtractor.java` (backend + Android). |
| `synth_phishing.py` | generates the positive class (phishing grammar) + augmented legit URLs with paths. |
| `train_url_model.py` | trains LogisticRegression, writes `src/main/resources/ml/url_model.json`. |
| `../src/main/resources/ml/url_model.json` | the deployed model (scaler + coefficients + anomaly baselines + metrics). Also copied to `cybershield-android/app/src/main/assets/ml/`. |

## Retrain

```bash
pip install scikit-learn numpy
python ml/train_url_model.py --csv "path/to/extended_legitimate_urls_dataset_12k.csv"
# then copy the json to the Android assets:
cp src/main/resources/ml/url_model.json ../cybershield-android/app/src/main/assets/ml/
```

Then run `com.cybershield.url.UrlFeatureParityTest` — it fails if the Java feature
extractor drifts from the Python one.

## About the training data

`extended_legitimate_urls_dataset_12k.csv` is **legitimate-only and synthetic**
(no real domains, no paths). So:

* **negatives** = that dataset + ~3k generated legit URLs *with realistic paths* on
  real well-known domains (so the model doesn't learn "has a path ⇒ bad").
* **positives** = ~8k URLs built from documented phishing grammar and by perturbing
  legit domains (typosquat, IP host, deep deceptive subdomains, credential keywords,
  `@`-trick, punycode, shortener wrap, suspicious-TLD brand combos, `%`-encoded paths).

Held-out metrics in `url_model.json` are high (AUC ≈ 1.0) **because both classes are
partly synthetic and thus very separable** — treat them as a sanity check, not a
real-world accuracy claim. That is exactly why the model is used as a bounded
contributor, alongside the deterministic policies and live threat intelligence.

To improve realism, add a real labelled phishing feed (PhishTank / OpenPhish dumps)
as additional positives and retrain — the pipeline and feature contract don't change.
