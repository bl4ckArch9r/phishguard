#!/usr/bin/env python
"""Generate a SYNTHETIC URL dataset so the pipeline can be smoke-tested offline.

!!! DO NOT REPORT METRICS TRAINED ON THIS FILE !!!
The phishing/legit patterns here are invented by this script, so any model will
score unrealistically well or badly. For the report, train on a real dataset
(PhishTank / OpenPhish for phishing + Tranco top sites for legitimate URLs, or
a Kaggle phishing-URL dataset) with:   python train.py --data your_file.csv
"""
import csv
import random
import string
import sys

random.seed(7)
LEGIT_DOMAINS = ["wikipedia.org", "github.com", "stackoverflow.com", "bbc.co.uk", "nytimes.com",
                 "mit.edu", "python.org", "mozilla.org", "slit.lk", "gov.lk", "cnn.com",
                 "medium.com", "reuters.com", "w3.org", "arxiv.org", "nature.com", "ieee.org",
                 "udemy.com", "coursera.org", "kaggle.com", "openai.com", "docker.com",
                 "ubuntu.com", "gnu.org", "apache.org", "npmjs.com", "cloudflare.com"]
PATHS = ["", "/", "/about", "/docs/intro", "/blog/2024/post-title", "/products/list", "/en/index.html",
         "/search?q=security", "/news/world/article-123", "/wiki/Information_security"]
BRANDS = ["paypal", "google", "microsoft", "apple", "amazon", "facebook", "netflix", "commercialbank",
          "sampath", "dialog", "icloud", "instagram"]
WORDS = ["login", "secure", "verify", "update", "account", "signin", "confirm", "support"]
TLDS = ["com", "net", "xyz", "top", "info", "co", "click", "online"]


def rnd(n):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def legit():
    d = random.choice(LEGIT_DOMAINS)
    sub = random.choice(["", "www.", "en.", "docs.", "blog."])
    return f"{random.choice(['https', 'https', 'https', 'http'])}://{sub}{d}{random.choice(PATHS)}"


def phish():
    b = random.choice(BRANDS)
    w1, w2 = random.sample(WORDS, 2)
    k = random.random()
    tld = random.choice(TLDS)
    if k < 0.25:
        host = f"{b}-{w1}-{rnd(random.randint(3, 6))}.{tld}"
    elif k < 0.5:
        host = f"{w1}.{b}.{rnd(random.randint(6, 12))}.{tld}"
    elif k < 0.65:
        host = ".".join(str(random.randint(1, 254)) for _ in range(4))
    elif k < 0.8:
        host = f"{b.replace('o', '0').replace('l', '1')}{rnd(2)}.{tld}"
    else:
        host = f"{w1}-{w2}-{rnd(random.randint(5, 9))}.{tld}"
    path = random.choice(["/login", f"/{w1}/{w2}.php", f"/{b}/{w1}?id={rnd(8)}", "/index.php?session=" + rnd(16)])
    return f"{random.choice(['http', 'http', 'https'])}://{host}{path}"


rows = [(legit(), 0) for _ in range(3000)] + [(phish(), 1) for _ in range(3000)]
random.shuffle(rows)
out = sys.argv[1] if len(sys.argv) > 1 else "data/synthetic_urls.csv"
with open(out, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["url", "label"])
    w.writerows(rows)
print(f"wrote {out} ({len(rows)} rows) - SYNTHETIC, for smoke tests only")
