#!/usr/bin/env python
"""Download the Tranco top-sites list and keep the top N registered domains.

    python tools/fetch_top_domains.py            # top 10,000 -> data/top_domains.txt
    python tools/fetch_top_domains.py --top 50000

Used by risk.py to stop the address-only AI score from flagging the homepage of
a very popular site. Needs internet. List: https://tranco-list.eu (cite it in the report).
"""
import argparse
import io
import sys
import zipfile
from pathlib import Path

import httpx

URL = "https://tranco-list.eu/top-1m.csv.zip"
OUT = Path(__file__).resolve().parent.parent / "data" / "top_domains.txt"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=10_000)
    a = ap.parse_args()
    r = httpx.get(URL, timeout=120, follow_redirects=True)
    r.raise_for_status()
    z = zipfile.ZipFile(io.BytesIO(r.content))
    lines = z.read(z.namelist()[0]).decode().splitlines()[: a.top]
    domains = [ln.split(",", 1)[1].strip().lower() for ln in lines if "," in ln]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(domains) + "\n")
    print(f"saved {len(domains)} domains -> {OUT}")


if __name__ == "__main__":
    sys.exit(main())
