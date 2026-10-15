#!/usr/bin/env python
"""Build a broader training CSV: your base dataset + many small legitimate domains.

    python tools/build_dataset.py --base data/urls.csv --out data/urls_plus.csv
    python train.py --data data/urls_plus.csv --max-rows 350000

Why: the Kaggle file's legitimate URLs are mostly a few big sites with deep pages, so a
model trained on it learns "unfamiliar domain = phishing" and flags ordinary small sites
(e.g. a university's .lk address). Adding the Tranco top sites as host-only legitimate
examples shows it thousands of ordinary domains and many country endings.

Adds
  * legitimate: top N registered domains of the Tranco list (https://tranco-list.eu, needs internet)
  * phishing:   data/blocklist.txt if it exists (OpenPhish feed, see README: threat_intel refresh)

Caveats to state in the report: Tranco is a popularity ranking, not a guarantee of safety; the
phishing and legitimate examples still come from different sources, so evaluate on a held-out
set from a third source before claiming real-world accuracy.
"""
import argparse
import io
import sys
import zipfile
from pathlib import Path

import httpx
import pandas as pd

HERE = Path(__file__).resolve().parent.parent
URL = "https://tranco-list.eu/top-1m.csv.zip"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=str(HERE / "data" / "urls.csv"))
    ap.add_argument("--out", default=str(HERE / "data" / "urls_plus.csv"))
    ap.add_argument("--tranco-top", type=int, default=500_000, help="use the top N ranked domains ...")
    ap.add_argument("--tranco-sample", type=int, default=120_000,
                    help="... and sample this many of them at random, so small, long-tail sites "
                         "(like a university's .lk address) are represented, not just famous ones")
    ap.add_argument("--base-max", type=int, default=150_000, help="rows sampled from the base file (0 = all)")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()

    base = pd.read_csv(a.base)
    ucol = next(c for c in ("URL", "url", "Url") if c in base.columns)
    lcol = next(c for c in ("Label", "label", "type", "class") if c in base.columns)
    base = base[[ucol, lcol]].rename(columns={ucol: "URL", lcol: "Label"})
    base["URL"] = base["URL"].astype(str).str.strip()
    base = base.drop_duplicates("URL")
    if a.base_max and len(base) > a.base_max:
        base = base.sample(a.base_max, random_state=a.seed)
    parts = [base]
    print(f"[base] {len(base)} rows from {a.base}")

    r = httpx.get(URL, timeout=180, follow_redirects=True)
    r.raise_for_status()
    z = zipfile.ZipFile(io.BytesIO(r.content))
    lines = z.read(z.namelist()[0]).decode().splitlines()[: a.tranco_top]
    domains = [ln.split(",", 1)[1].strip().lower() for ln in lines if "," in ln]
    if a.tranco_sample and len(domains) > a.tranco_sample:
        import random
        domains = random.Random(a.seed).sample(domains, a.tranco_sample)
    parts.append(pd.DataFrame({"URL": domains, "Label": "good"}))
    print(f"[tranco] {len(domains)} legitimate domains")

    bl = HERE / "data" / "blocklist.txt"
    if bl.exists():
        feed = [ln.strip() for ln in bl.read_text(errors="ignore").splitlines()
                if ln.strip() and not ln.startswith("#")]
        parts.append(pd.DataFrame({"URL": feed, "Label": "bad"}))
        print(f"[feed] {len(feed)} phishing URLs from {bl.name}")
    else:
        print("[feed] data/blocklist.txt not found; run 'python -m phishguard.threat_intel refresh' to add current phishing URLs")

    out = pd.concat(parts, ignore_index=True).drop_duplicates("URL")
    out.to_csv(a.out, index=False)
    print(f"[saved] {len(out)} rows -> {a.out}\n{out['Label'].value_counts().to_string()}")


if __name__ == "__main__":
    sys.exit(main())
