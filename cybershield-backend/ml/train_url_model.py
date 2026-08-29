"""
Train the Cyber Shield URL risk model.

  python ml/train_url_model.py --csv "C:/path/extended_legitimate_urls_dataset_12k.csv"

Output: src/main/resources/ml/url_model.json  (loaded by the Java + Android engines)

The model is a plain, L2-regularised LogisticRegression on ~24 lexical features,
class-weight balanced. It is deliberately small and interpretable: it exports as
a scaler (mean/scale) + a coefficient vector + intercept. It returns a
PROBABILITY that is fed into the rule-based risk engine as a single capped
signal — it never decides a verdict on its own.
"""
from __future__ import annotations
import argparse
import csv
import json
import math
import os
import sys
from datetime import datetime, timezone

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, precision_recall_fscore_support, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from url_features import FEATURES, extract, vector          # noqa: E402
from synth_phishing import gen_positives, gen_legit_with_paths  # noqa: E402

OUT = os.path.normpath(os.path.join(HERE, "..", "src", "main", "resources", "ml", "url_model.json"))


def load_dataset_urls(csv_path):
    urls = []
    with open(csv_path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            u = (row.get("url") or "").strip()
            if u:
                urls.append(u)
    return urls


def pctl(arr, p):
    return float(np.percentile(np.asarray(arr, dtype=float), p))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="path to extended_legitimate_urls_dataset_12k.csv")
    ap.add_argument("--pos", type=int, default=9000, help="synthetic phishing samples")
    ap.add_argument("--legit-paths", type=int, default=4000, help="augmented legit URLs with paths")
    args = ap.parse_args()

    legit = load_dataset_urls(args.csv)
    print(f"dataset legit URLs           : {len(legit)}")
    legit_aug = gen_legit_with_paths(args.legit_paths)
    print(f"augmented legit (with paths) : {len(legit_aug)}")
    phish = gen_positives(args.pos)
    print(f"synthetic phishing           : {len(phish)}")

    X_urls = legit + legit_aug + phish
    y = np.array([0] * (len(legit) + len(legit_aug)) + [1] * len(phish))
    X = np.array([vector(u) for u in X_urls], dtype=float)

    # anomaly baselines: from the REAL dataset negatives only
    base = np.array([vector(u) for u in legit], dtype=float)
    bidx = {name: i for i, name in enumerate(FEATURES)}
    baseline = {
        "url_length_p99": pctl(base[:, bidx["url_length"]], 99),
        "url_entropy_p99": pctl(base[:, bidx["url_entropy"]], 99),
        "host_entropy_p99": pctl(base[:, bidx["host_entropy"]], 99),
        "num_dots_p99": pctl(base[:, bidx["num_dots"]], 99),
        "num_hyphens_p99": pctl(base[:, bidx["num_hyphens"]], 99),
    }

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    scaler = StandardScaler().fit(Xtr)
    clf = LogisticRegression(max_iter=2000, C=1.0, class_weight="balanced")
    clf.fit(scaler.transform(Xtr), ytr)

    proba = clf.predict_proba(scaler.transform(Xte))[:, 1]
    pred = (proba >= 0.5).astype(int)
    auc = roc_auc_score(yte, proba)
    pr, rc, f1, _ = precision_recall_fscore_support(yte, pred, average="binary")
    tn, fp, fn, tp = confusion_matrix(yte, pred).ravel()
    print("\n== held-out evaluation ==")
    print(f"ROC-AUC        : {auc:.4f}")
    print(f"precision      : {pr:.4f}")
    print(f"recall         : {rc:.4f}")
    print(f"f1             : {f1:.4f}")
    print(f"confusion      : TN={tn} FP={fp} FN={fn} TP={tp}")
    print(f"false-pos rate : {fp / (fp + tn):.4f}")

    coef = clf.coef_[0]
    order = np.argsort(np.abs(coef))[::-1]
    print("\n== top features by |weight| ==")
    for i in order[:12]:
        print(f"  {FEATURES[i]:<20} {coef[i]:+.3f}")

    model = {
        "_comment": "Cyber Shield URL risk model. LogisticRegression on lexical features. "
                    "Output is a probability fed to the rule engine as ONE capped signal.",
        "version": 1,
        "trained_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "features": FEATURES,
        "mean": [round(float(x), 6) for x in scaler.mean_],
        "scale": [round(float(x), 6) for x in scaler.scale_],
        "coef": [round(float(x), 6) for x in coef],
        "intercept": round(float(clf.intercept_[0]), 6),
        "baseline": {k: round(v, 4) for k, v in baseline.items()},
        "metrics": {
            "roc_auc": round(float(auc), 4),
            "precision": round(float(pr), 4),
            "recall": round(float(rc), 4),
            "f1": round(float(f1), 4),
            "false_positive_rate": round(float(fp / (fp + tn)), 4),
            "n_train": int(len(ytr)),
            "n_test": int(len(yte)),
            "n_legit_real": len(legit),
            "n_legit_aug": len(legit_aug),
            "n_phish_synth": len(phish),
        },
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(model, fh, indent=2)
    print(f"\nwrote {OUT}")

    # quick sanity spot-checks
    print("\n== spot checks (probability of phishing) ==")
    for u in [
        "https://www.google.com",
        "https://github.com/torvalds/linux",
        "http://paypa1-verify-login.tk/webscr?cmd=_login",
        "http://192.168.10.5/account/verify",
        "https://sbi.secure.login.co.in.kxj28fh.buzz/",
        "https://amazon.in/dp/B0ABCDEF12",
        "http://xn--pple-43d.com/signin",
    ]:
        v = np.array([vector(u)], dtype=float)
        p = clf.predict_proba(scaler.transform(v))[0, 1]
        print(f"  {p:5.3f}  {u}")


if __name__ == "__main__":
    main()
