#!/usr/bin/env python
"""Collect labelled PAGE CONTENT for the page-content AI model.

    python tools/collect_pages.py --n-phish 6000 --n-legit 6000        # about 1-2 hours, resumable
    python tools/collect_pages.py --n-phish 60 --n-legit 60 --out data/pages/test.jsonl   # quick test

Sources
  phishing  : OpenPhish feed + a spread of random chunks of the Phishing.Database "ACTIVE" list
              (GitHub, mitchellkrogza/Phishing.Database). Many entries are already dead, so only
              pages that actually answer are kept.
  legitimate: random registered domains from Tranco rank 1,000-500,000 (ordinary sites, not only
              famous ones). The final evaluation uses rank 500,000-1,000,000, so they never overlap.

Each URL is fetched ONCE with the guarded fetcher (public addresses only, size-capped, nothing
submitted, nothing executed). We store the page's text blob and structure numbers, never the raw HTML.

Quality rules (so the model learns pages, not accidents)
  * pages the scanner cannot read are dropped: HTTP errors, network-filter pages, hosting
    suspension pages, and the hosting provider's own malware interstitial (that would label the
    interstitial text as "phishing content");
  * empty pages are dropped;
  * at most N pages per registered domain, and near-duplicates (same title + opening text) are
    capped, because phishing kits copy one page hundreds of times and would dominate training.

Use a network WITHOUT a web filter (a phone hotspot), otherwise the filter's block page is what you get.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import io
import json
import random
import sys
import time
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))

import httpx  # noqa: E402

from phishguard import features as F  # noqa: E402
from phishguard.netguard import safe_fetch  # noqa: E402
from phishguard.page_model import extract  # noqa: E402
from phishguard.pipeline import unusable_page  # noqa: E402

OPENPHISH = "https://openphish.com/feed.txt"
PDB = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"
TRANCO = "https://tranco-list.eu/top-1m.csv.zip"


def _host(u: str) -> str:
    try:
        return (urlsplit(u).hostname or "").lower()
    except ValueError:
        return ""


def phishing_urls(n: int, seed: int, per_domain: int) -> list[str]:
    rnd = random.Random(seed)
    urls: list[str] = []
    try:
        r = httpx.get(OPENPHISH, timeout=60, follow_redirects=True)
        urls += [l.strip() for l in r.text.splitlines() if l.strip().startswith("http")]
        print(f"[phish] OpenPhish: {len(urls)} URLs")
    except Exception as e:
        print(f"[phish] OpenPhish unavailable: {e}")
    # Phishing.Database: ~65 MB. Read 12 random 1.5 MB chunks instead of the whole file.
    try:
        size = int(httpx.head(PDB, headers={"Accept-Encoding": "identity"}, timeout=30,
                              follow_redirects=True).headers["content-length"])
        got = 0
        for _ in range(12):
            start = rnd.randrange(0, max(size - 1_500_000, 1))
            rr = httpx.get(PDB, headers={"Range": f"bytes={start}-{start + 1_500_000}", "Accept-Encoding": "identity"},
                           timeout=90, follow_redirects=True)
            lines = rr.text.splitlines()[1:-1]
            chunk = [l.strip() for l in lines if l.strip().startswith("http")]
            urls += chunk
            got += len(chunk)
        print(f"[phish] Phishing.Database sample: {got} URLs")
    except Exception as e:
        print(f"[phish] Phishing.Database unavailable: {e}")
    rnd.shuffle(urls)
    seen_url, per_reg, out = set(), {}, []
    for u in urls:
        h = _host(u)
        if not h or u in seen_url:
            continue
        reg = F.registered_domain(h)
        if per_reg.get(reg, 0) >= per_domain:
            continue
        per_reg[reg] = per_reg.get(reg, 0) + 1
        seen_url.add(u)
        out.append(u)
    print(f"[phish] {len(out)} candidate URLs after per-domain cap ({per_domain}); will try until {n} usable pages")
    return out


def legit_urls(seed: int) -> list[str]:
    r = httpx.get(TRANCO, timeout=180, follow_redirects=True)
    z = zipfile.ZipFile(io.BytesIO(r.content))
    lines = z.read(z.namelist()[0]).decode().splitlines()[1_000:500_000]
    doms = [ln.split(",", 1)[1].strip().lower() for ln in lines if "," in ln]
    random.Random(seed).shuffle(doms)
    print(f"[legit] {len(doms)} candidate domains (Tranco rank 1,000-500,000)")
    return ["https://" + d + "/" for d in doms]


def done_urls(path: Path) -> dict:
    out = {"urls": set(), "counts": {0: 0, 1: 0}, "hashes": {}}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                d = json.loads(line)
            except Exception:
                continue
            out["urls"].add(d["url"])
            if not d.get("skip"):
                out["counts"][d["label"]] += 1
                out["hashes"][d["hash"]] = out["hashes"].get(d["hash"], 0) + 1
    return out


async def run(cands: list[tuple[str, int]], target: dict, out: Path, conc: int, dup_cap: int, per_reg_cap: dict):
    state = done_urls(out)
    sem = asyncio.Semaphore(conc)
    fh = out.open("a", encoding="utf-8")
    t0 = time.time()
    tried = {"n": 0}
    reg_counts: dict = {}

    async def one(url: str, label: int):
        if state["counts"][label] >= target[label] or url in state["urls"]:
            return
        async with sem:
            if state["counts"][label] >= target[label]:
                return
            rec = {"url": url, "label": label, "skip": True}
            try:
                fr = await asyncio.wait_for(safe_fetch(url), timeout=25)
                tried["n"] += 1
                if fr.ok and fr.html and len(fr.html) > 100:
                    head = fr.html[:4000]
                    if not unusable_page(fr.status, head):
                        blob, feats = extract(fr.final_url, fr.html)
                        if feats["n_forms"] or feats["n_inputs"] or feats["log_text_len"] > 2.5:
                            reg = F.registered_domain(_host(fr.final_url) or _host(url))
                            h = hashlib.md5((blob[:400]).encode()).hexdigest()
                            key = (label, reg)
                            if (state["hashes"].get(h, 0) < dup_cap
                                    and reg_counts.get(key, 0) < per_reg_cap[label]
                                    and state["counts"][label] < target[label]):
                                reg_counts[key] = reg_counts.get(key, 0) + 1
                                state["hashes"][h] = state["hashes"].get(h, 0) + 1
                                state["counts"][label] += 1
                                rec = {"url": url, "final": fr.final_url, "label": label, "reg": reg, "hash": h,
                                       "blob": blob, "feats": feats, "ts": int(time.time())}
            except Exception:
                tried["n"] += 1
            state["urls"].add(url)
            fh.write(json.dumps(rec) + "\n")
            fh.flush()
            if tried["n"] % 100 == 0:
                print(f"  tried {tried['n']}  kept phishing={state['counts'][1]}/{target[1]} "
                      f"legit={state['counts'][0]}/{target[0]}  {(time.time() - t0) / 60:.1f} min")

    try:
        await asyncio.gather(*(one(u, y) for u, y in cands))
    finally:
        fh.close()
    print(f"[done] kept phishing={state['counts'][1]} legit={state['counts'][0]}; tried {tried['n']} URLs")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-phish", type=int, default=6000)
    ap.add_argument("--n-legit", type=int, default=6000)
    ap.add_argument("--conc", type=int, default=16)
    ap.add_argument("--seed", type=int, default=5)
    ap.add_argument("--dup-cap", type=int, default=3, help="max pages with the same title+opening text")
    ap.add_argument("--phish-per-domain", type=int, default=6, help="max phishing pages per registered domain")
    ap.add_argument("--out", default=str(HERE / "data" / "pages" / "pages.jsonl"))
    ap.add_argument("--phish-file", help="own phishing URL list instead of downloading feeds")
    ap.add_argument("--legit-file", help="own legitimate URL list instead of Tranco")
    a = ap.parse_args()

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    ph = ([l.strip() for l in Path(a.phish_file).read_text().splitlines() if l.strip()]
          if a.phish_file else phishing_urls(a.n_phish, a.seed, a.phish_per_domain))
    lg = ([l.strip() for l in Path(a.legit_file).read_text().splitlines() if l.strip()]
          if a.legit_file else legit_urls(a.seed))
    ph, lg = ph[: a.n_phish * 12], lg[: a.n_legit * 4]       # enough spare candidates for dead/blocked ones
    # interleave so both classes progress together and a stop halfway stays balanced
    cands, i = [], 0
    while i < max(len(ph), len(lg)):
        if i < len(ph):
            cands.append((ph[i], 1))
        if i < len(lg):
            cands.append((lg[i], 0))
        i += 1
    print(f"[plan] {len(cands)} candidate URLs, target phishing={a.n_phish} legit={a.n_legit}, output {out}")
    try:
        asyncio.run(run(cands, {1: a.n_phish, 0: a.n_legit}, out, a.conc, a.dup_cap,
                        {1: a.phish_per_domain, 0: 1}))
    except KeyboardInterrupt:
        print("\n[stopped] progress is saved; run the same command to resume")


if __name__ == "__main__":
    main()
