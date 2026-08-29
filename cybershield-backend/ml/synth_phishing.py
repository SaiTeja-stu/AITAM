"""
Synthetic positive (phishing-like) URL generator + augmented legitimate URLs.

The provided dataset is legitimate-only and path-less, so:
  * negatives  = the dataset  +  realistic legit URLs WITH paths/queries on real
                 well-known domains (so the model doesn't learn "has a path => bad")
  * positives  = URLs built from documented phishing grammar and from perturbing
                 legit domains (typosquat, IP host, deep subdomains, credential
                 keywords, @-trick, punycode, shortener wrap, suspicious TLD, ...)

Everything is generated locally and deterministically (seeded). No live URLs.
"""
from __future__ import annotations
import random

BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "sbi", "hdfc", "icici", "axis", "paytm", "phonepe",
    "flipkart", "irctc", "linkedin", "outlook", "gmail", "binance", "coinbase",
]
REAL_DOMAINS = [
    "google.com", "youtube.com", "github.com", "en.wikipedia.org", "amazon.in",
    "flipkart.com", "linkedin.com", "microsoft.com", "apple.com", "netflix.com",
    "paypal.com", "stackoverflow.com", "reddit.com", "medium.com", "nytimes.com",
    "bbc.co.uk", "sbi.co.in", "hdfcbank.com", "icicibank.com", "irctc.co.in",
    "docs.google.com", "drive.google.com", "mail.google.com", "play.google.com",
    "developer.mozilla.org", "npmjs.com", "pypi.org", "gitlab.com", "bitbucket.org",
]
REAL_PATHS = [
    "/", "/about", "/help/faq", "/wiki/Cyber_security", "/dp/B0ABCDEF12",
    "/user/repo/issues/42", "/watch?v=dQw4w9WgXcQ", "/search?q=how+to+bake+bread",
    "/questions/12345/how-do-i", "/document/d/1a2B3c4D5e/edit", "/in/some-person",
    "/settings/profile", "/2024/01/15/some-article.html", "/products?page=3&sort=price",
    "/account/orders", "/status/1750000000000000000",
]
SUS_TLD = ["tk", "top", "xyz", "club", "gq", "cf", "ml", "buzz", "online", "click"]
GOOD_TLD = ["com", "net", "org", "io", "co", "in"]
CRED_PATHS = [
    "/login", "/signin", "/verify", "/account/verify", "/secure/login",
    "/update-password", "/kyc/confirm", "/webscr/verify", "/auth/confirm-identity",
    "/wallet/unlock", "/billing/update", "/refund/claim", "/otp/confirm",
]
RAND_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789"


def _rand_label(rng, lo=6, hi=14):
    return "".join(rng.choice(RAND_CHARS) for _ in range(rng.randint(lo, hi)))


def _typosquat(rng, brand):
    tricks = [
        brand.replace("o", "0"), brand.replace("l", "1"), brand.replace("i", "1"),
        brand.replace("e", "3"), brand + "-secure", "secure-" + brand,
        brand + "-verify", brand + "-login", brand[:-1] + brand[-1] * 2,
        brand + "s", "my-" + brand, brand.replace("a", "@").replace("@", "a"),
        brand + rng.choice(["support", "help", "team", "care"]),
    ]
    return rng.choice([t for t in tricks if t != brand])


def gen_positives(n, seed=1):
    rng = random.Random(seed)
    out = set()
    kinds = 11
    attempts = 0
    while len(out) < n and attempts < n * 40:
        attempts += 1
        k = rng.randrange(kinds)
        b = rng.choice(BRANDS)
        if k == 0:  # typosquat domain
            u = f"http://{_typosquat(rng, b)}.{rng.choice(SUS_TLD + GOOD_TLD)}{rng.choice(CRED_PATHS)}"
        elif k == 1:  # IP host
            ip = ".".join(str(rng.randint(1, 254)) for _ in range(4))
            u = f"http://{ip}{rng.choice(CRED_PATHS)}"
        elif k == 2:  # deep deceptive subdomains ending in attacker domain
            u = (f"http://{b}.{rng.choice(['secure','login','account','verify'])}."
                 f"{rng.choice(['com','co','net'])}.{_rand_label(rng)}.{rng.choice(SUS_TLD)}/")
        elif k == 3:  # brand as subdomain of unrelated domain
            u = f"https://{b}-{rng.choice(['login','secure','verify'])}.{_rand_label(rng)}.{rng.choice(SUS_TLD)}{rng.choice(CRED_PATHS)}"
        elif k == 4:  # @ trick
            u = f"https://{rng.choice(REAL_DOMAINS)}@{_typosquat(rng, b)}.{rng.choice(SUS_TLD)}/"
        elif k == 5:  # punycode
            u = f"https://xn--{_rand_label(rng, 4, 8)}-{rng.choice('0123456789abcde')}{rng.choice('0123456789abcde')}d.{rng.choice(GOOD_TLD)}{rng.choice(CRED_PATHS)}"
        elif k == 6:  # excessive hyphens
            u = (f"http://{b}-" + "-".join(rng.choice(['secure', 'login', 'verify', 'account', 'update', 'confirm'])
                 for _ in range(rng.randint(3, 5))) + f".{rng.choice(SUS_TLD + GOOD_TLD)}/")
        elif k == 7:  # random high-entropy host on abused TLD
            u = f"http://{_rand_label(rng, 10, 18)}.{rng.choice(SUS_TLD)}{rng.choice(CRED_PATHS)}"
        elif k == 8:  # hex / traversal encoded path
            u = f"http://{_typosquat(rng, b)}.{rng.choice(GOOD_TLD)}/%2e%2e%2f{rng.choice(['login','verify'])}%00.php"
        elif k == 9:  # long credential query string
            u = (f"http://{_typosquat(rng, b)}.{rng.choice(SUS_TLD)}/webscr?cmd=_login-run&dispatch="
                 f"{_rand_label(rng, 20, 30)}&{b}=verify")
        else:  # brand token buried, many dots
            u = f"http://www.{b}.com.{_rand_label(rng)}.{_rand_label(rng)}.{rng.choice(SUS_TLD)}/signin"
        out.add(u)
    return list(out)


def gen_legit_with_paths(n, seed=2):
    rng = random.Random(seed)
    out = set()
    attempts = 0
    while len(out) < n and attempts < n * 40:
        attempts += 1
        d = rng.choice(REAL_DOMAINS)
        p = rng.choice(REAL_PATHS)
        # append a realistic id/slug so we can generate arbitrarily many uniques
        if p not in ("/", "/about") and rng.random() < 0.7:
            tail = rng.choice([
                f"/{_rand_label(rng, 4, 10)}",
                f"?id={rng.randint(1000, 9_999_999)}",
                f"-{rng.randint(1, 999)}",
                f"/{rng.randint(2015, 2025)}/{rng.randint(1, 12):02d}",
            ])
            p = p + tail
        scheme = "https" if rng.random() < 0.9 else "http"
        host = d if rng.random() < 0.7 else "www." + d
        out.add(f"{scheme}://{host}{p}")
    return list(out)
