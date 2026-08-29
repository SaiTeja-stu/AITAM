"""
Lexical URL feature extraction — the single source of truth.

Every feature here is computable from the URL STRING alone (no DNS, no fetch),
so the exact same logic is reimplemented byte-for-byte in:
  - backend : com.cybershield.analyze.ml.UrlFeatureExtractor (Java)
  - android : com.cybershield.core.ml.UrlFeatureExtractor (Java)

If you change a feature, change all three and retrain.
"""
from __future__ import annotations
import math
import re
from urllib.parse import urlsplit

# Keep this list in sync with the Java side.
FEATURES = [
    "url_length", "host_length", "path_length", "query_length",
    "num_dots", "num_hyphens", "num_digits", "num_special",
    "num_subdomains", "num_params",
    "has_ip", "has_at", "has_punycode", "pct_encoded",
    "suspicious_tld", "is_https", "is_shortener",
    "host_entropy", "url_entropy",
    "suspicious_keywords", "longest_token", "digit_ratio_host",
    "hyphen_in_domain", "tld_length",
]

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "club", "online", "click", "country",
    "gq", "cf", "tk", "ml", "work", "support", "rest", "fit", "buzz",
    "info", "biz",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "bl.ink",
    "t.ly", "short.io",
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "account", "secure",
    "security", "update", "password", "wallet", "payment", "refund",
    "reward", "prize", "claim", "bank", "otp", "kyc", "invoice", "urgent",
    "confirm", "unlock", "suspend", "recover",
]

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def extract(url: str) -> dict:
    raw = (url or "").strip()
    if not re.match(r"(?i)^[a-z][a-z0-9+.\-]*://", raw):
        raw = "http://" + raw
    parts = urlsplit(raw)
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower().rstrip(".")
    path = parts.path or ""
    query = parts.query or ""
    labels = host.split(".") if host else []
    tld = labels[-1] if len(labels) >= 2 else ""
    # registrable-ish domain = last two labels
    domain = ".".join(labels[-2:]) if len(labels) >= 2 else host
    domain_label = labels[-2] if len(labels) >= 2 else host

    host_no_www = labels[1:] if labels[:1] == ["www"] else labels
    num_subdomains = max(0, len(host_no_www) - 2)

    lower_hp = (host + path).lower()
    digits_host = sum(c.isdigit() for c in host)

    f = {
        "url_length": len(raw),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": raw.count("."),
        "num_hyphens": raw.count("-"),
        "num_digits": sum(c.isdigit() for c in raw),
        "num_special": sum(not c.isalnum() and c not in "./:-_?=&%@" for c in raw),
        "num_subdomains": num_subdomains,
        "num_params": len([p for p in query.split("&") if p]) if query else 0,
        "has_ip": 1 if _IPV4.match(host) else 0,
        "has_at": 1 if "@" in raw.split("://", 1)[-1] else 0,
        "has_punycode": 1 if "xn--" in host else 0,
        "pct_encoded": len(re.findall(r"%[0-9a-fA-F]{2}", raw)),
        "suspicious_tld": 1 if tld in SUSPICIOUS_TLDS else 0,
        "is_https": 1 if scheme == "https" else 0,
        "is_shortener": 1 if domain in SHORTENERS else 0,
        "host_entropy": round(_entropy(host), 4),
        "url_entropy": round(_entropy(raw), 4),
        "suspicious_keywords": sum(1 for k in SUSPICIOUS_KEYWORDS if k in lower_hp),
        "longest_token": max((len(t) for t in re.split(r"[.\-_]", host) if t), default=0),
        "digit_ratio_host": round(digits_host / len(host), 4) if host else 0.0,
        "hyphen_in_domain": 1 if "-" in domain_label else 0,
        "tld_length": len(tld),
    }
    return f


def vector(url: str) -> list[float]:
    f = extract(url)
    return [float(f[name]) for name in FEATURES]
