#!/usr/bin/env python
"""End-to-end evaluation of the WHOLE PhishGuard pipeline on data the model has never seen.

    python tools/evaluate_system.py --n 200            # 200 phishing + 200 legitimate (about 20-40 min)
    python tools/evaluate_system.py --n 20 --no-deep   # quick smoke test (URL + model only)
    python tools/evaluate_system.py --report-only      # rebuild the tables from results already saved

What it measures
  * phishing  : FRESH URLs from the live OpenPhish feed, minus anything in data/blocklist.txt or
                data/urls_plus.csv (the training data), so the model has not seen them.
  * legitimate: random domains from Tranco rank 500,001-1,000,000. Training only sampled the top
                500,000, so these are unseen, ordinary, long-tail sites (not famous ones), and they
                are far outside the top-10k list that triggers the "top site" score cap.
  * The threat-feed score floor is DISABLED. Otherwise every OpenPhish URL scores 100 just because
    it is listed, which would measure the feed and not the system.

Each URL goes through the real pipeline (URL features, AI model, brand checks, page, rendered
behaviour, domain age, certificate). Results are appended to data/eval/results.jsonl as they finish,
so you can stop (Ctrl+C) and re-run to resume.

Honest limits (state them in the report)
  * Phishing pages are short-lived. Many OpenPhish URLs are already dead when scanned, so the page and
    behaviour layers could not run for them. The table splits results by "page inspected" so you can
    see how much of the score came from the URL/AI alone.
  * Legitimate = "ranked by Tranco", not "guaranteed safe". A few may be parked, dead or compromised.
  * Both sets come from different sources. This is a much better estimate than the dataset split, but
    still a sample, not the real-world rate. Read the confidence intervals.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import io
import json
import math
import os
import random
import sys
import time
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))

import httpx  # noqa: E402

EVAL = HERE / "data" / "eval"
RESULTS = EVAL / "results.jsonl"
TRANCO = "https://tranco-list.eu/top-1m.csv.zip"
OPENPHISH = "https://openphish.com/feed.txt"


# --------------------------------------------------------------------------- datasets
def _host(u: str) -> str:
    try:
        return (urlsplit(u if "://" in u else "http://" + u).hostname or "").lower()
    except ValueError:
        return ""


def _training_hosts() -> set[str]:
    hosts: set[str] = set()
    bl = HERE / "data" / "blocklist.txt"
    if bl.exists():
        hosts |= {_host(l.strip()) for l in bl.read_text(errors="ignore").splitlines() if l.strip()}
    plus = HERE / "data" / "urls_plus.csv"
    if plus.exists():
        with plus.open(newline="", encoding="utf-8", errors="ignore") as f:
            for row in csv.DictReader(f):
                hosts.add(_host(row.get("URL", "")))
    for pf_ in (HERE / "data" / "pages").glob("*.jsonl"):          # page-model training pages
        for line in pf_.read_text(encoding="utf-8").splitlines():
            try:
                d = json.loads(line)
            except Exception:
                continue
            hosts.add(_host(d.get("url", "")))
            hosts.add(_host(d.get("final", "")))
    hosts.discard("")
    return hosts


def fresh_phishing(n: int, seed: int, exclude: set[str]) -> list[str]:
    r = httpx.get(OPENPHISH, timeout=60, follow_redirects=True)
    r.raise_for_status()
    urls = [l.strip() for l in r.text.splitlines() if l.strip().startswith(("http://", "https://"))]
    seen_hosts, out = set(), []
    random.Random(seed).shuffle(urls)
    for u in urls:                                   # one URL per host, none seen in training
        h = _host(u)
        if h and h not in exclude and h not in seen_hosts:
            seen_hosts.add(h)
            out.append(u)
    print(f"[phish] feed has {len(urls)} URLs; {len(out)} are new hosts; using {min(n, len(out))}")
    return out[:n]


def unseen_legit(n: int, seed: int, exclude: set[str]) -> list[str]:
    r = httpx.get(TRANCO, timeout=180, follow_redirects=True)
    r.raise_for_status()
    z = zipfile.ZipFile(io.BytesIO(r.content))
    lines = z.read(z.namelist()[0]).decode().splitlines()[500_000:1_000_000]
    doms = [ln.split(",", 1)[1].strip().lower() for ln in lines if "," in ln]
    doms = [d for d in doms if d not in exclude]
    random.Random(seed).shuffle(doms)
    print(f"[legit] Tranco rank 500k-1M: {len(doms)} candidates; using {min(n, len(doms))}")
    return doms[:n]


def read_list(p: str) -> list[str]:
    return [l.strip() for l in Path(p).read_text(errors="ignore").splitlines()
            if l.strip() and not l.startswith("#")]


# --------------------------------------------------------------------------- scanning
def _done() -> dict[str, dict]:
    out = {}
    if RESULTS.exists():
        for line in RESULTS.read_text(encoding="utf-8").splitlines():
            try:
                d = json.loads(line)
                out[d["input"]] = d
            except Exception:
                pass
    return out


async def scan_all(items: list[tuple[str, int]], deep: bool, conc: int):
    from phishguard import browser_analyzer, pipeline, threat_intel

    threat_intel.local_feed_lookup = lambda url: None          # no feed floor (see docstring)
    done = _done()
    todo = [(u, y) for u, y in items if u not in done]
    print(f"[scan] {len(items)} URLs, {len(done)} already done, {len(todo)} to scan "
          f"(deep={deep}, concurrency={conc})")
    sem = asyncio.Semaphore(conc)
    EVAL.mkdir(parents=True, exist_ok=True)
    fh = RESULTS.open("a", encoding="utf-8")
    count = {"n": 0}
    t0 = time.time()

    async def one(u: str, y: int):
        async with sem:
            rec = {"input": u, "label": y}
            try:
                r = await asyncio.wait_for(pipeline.analyze(u, deep=deep), timeout=90)
                f = r.get("facts", {})
                pf = f.get("page", {})
                rec.update(
                    url=r["url"], score=r["score"], verdict=r["verdict"],
                    ai=(r["model"] or {}).get("probability"),
                    page=bool(r["page_fetch"].get("ok")) if deep else False,
                    status=r["page_fetch"].get("status"), final=r["page_fetch"].get("final_url"),
                    title=pf.get("title"), text_len=pf.get("text_length"), forms=pf.get("forms"),
                    page_ai=(f.get("page_ai") or {}).get("probability"),
                    pw=pf.get("password_fields"), blocked=pf.get("blocked"), tls=str(f.get("domain", {}).get("tls"))[:60],
                    rendered=bool(f.get("browser", {}).get("rendered")),
                    layers=r["coverage"] if isinstance(r["coverage"], (dict, list)) else str(r["coverage"]),
                    top_evidence=[e["title"] for e in r["evidence"] if e["points"] > 0][:5],
                    ev={e["id"]: e["points"] for e in r["evidence"] if e["points"] > 0},   # for learned-fusion experiments
                    breakdown=r["breakdown"],
                    ms=r["duration_ms"])
            except Exception as e:                                   # a failed scan is recorded, not hidden
                rec.update(error=f"{type(e).__name__}: {e}"[:200])
            fh.write(json.dumps(rec) + "\n")
            fh.flush()
            count["n"] += 1
            if count["n"] % 10 == 0:
                el = time.time() - t0
                print(f"  {count['n']}/{len(todo)} done, {el/60:.1f} min elapsed")

    try:
        await asyncio.gather(*(one(u, y) for u, y in todo))
    finally:
        fh.close()
        await browser_analyzer.close()


# --------------------------------------------------------------------------- reporting
def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def _pct(k, n):
    if n == 0:
        return "n/a"
    lo, hi = wilson(k, n)
    return f"{100*k/n:5.1f}%  (95% CI {100*lo:.1f}-{100*hi:.1f}, {k}/{n})"


def confusion(rows, pred):
    tp = sum(1 for r in rows if r["label"] == 1 and pred(r))
    fn = sum(1 for r in rows if r["label"] == 1 and not pred(r))
    fp = sum(1 for r in rows if r["label"] == 0 and pred(r))
    tn = sum(1 for r in rows if r["label"] == 0 and not pred(r))
    return tp, fn, fp, tn


def block(title, rows, pred):
    tp, fn, fp, tn = confusion(rows, pred)
    n = tp + fn + fp + tn
    out = [f"{title}  (phishing={tp+fn}, legitimate={fp+tn})"]
    if n == 0:
        return out + ["  no rows"]
    out += [f"  accuracy   {_pct(tp+tn, n)}",
            f"  recall     {_pct(tp, tp+fn)}      (phishing caught)",
            f"  FNR        {_pct(fn, tp+fn)}      (phishing missed)",
            f"  FPR        {_pct(fp, fp+tn)}      (legitimate wrongly flagged)",
            f"  precision  {_pct(tp, tp+fp)}"]
    return out


def report(deep: bool):
    rows_all = list(_done().values())
    errs = [r for r in rows_all if "error" in r]
    rows = [r for r in rows_all if "error" not in r]
    lines = [f"PhishGuard end-to-end evaluation: {len(rows)} scanned ok, {len(errs)} scan errors (excluded)", ""]
    ph = [r for r in rows if r["label"] == 1]
    lg = [r for r in rows if r["label"] == 0]
    lines += [f"set sizes: phishing={len(ph)}, legitimate={len(lg)}",
              "feed floor disabled; legitimate = Tranco rank 500k-1M; phishing = fresh OpenPhish", ""]

    lines += block("FULL SYSTEM, flagged = verdict 'phishing' (score >= 65)", rows, lambda r: r["score"] >= 65) + [""]
    lines += block("FULL SYSTEM, flagged = 'suspicious' or worse (score >= 35)", rows, lambda r: r["score"] >= 35) + [""]
    ai = [r for r in rows if r.get("ai") is not None]
    lines += block("AI URL MODEL ALONE, flagged = probability >= 0.5", ai, lambda r: r["ai"] >= 0.5) + [""]

    if deep:
        why = {}
        for r in rows:
            if r.get("blocked"):
                why[(r["label"], r["blocked"])] = why.get((r["label"], r["blocked"]), 0) + 1
        if why:
            lines.append("pages the scanner could NOT read (not counted as inspected):")
            lines += [f"  {'phishing' if k[0] else 'legit':8} {k[1]:15} {v}" for k, v in sorted(why.items())] + [""]
        for name, key in (("page inspected", True), ("page NOT inspected (dead/blocked)", False)):
            sub = [r for r in rows if bool(r.get("page")) is key]
            lines += block(f"FULL SYSTEM (>=65), {name}", sub, lambda r: r["score"] >= 65) + [""]

    try:
        from sklearn.metrics import roc_auc_score
        if ph and lg:
            lines.append(f"ROC-AUC of the final score: {roc_auc_score([r['label'] for r in rows], [r['score'] for r in rows]):.3f}")
            if len(ai) > 10 and {r['label'] for r in ai} == {0, 1}:
                lines.append(f"ROC-AUC of the AI model alone: {roc_auc_score([r['label'] for r in ai], [r['ai'] for r in ai]):.3f}")
    except Exception:
        pass

    miss = sorted((r for r in ph if r["score"] < 65), key=lambda r: r["score"])
    fps = sorted((r for r in lg if r["score"] >= 35), key=lambda r: -r["score"])
    lines += ["", f"MISSED PHISHING (score < 65): {len(miss)}"]
    lines += [f"  {r['score']:>3}  ai={r.get('ai') if r.get('ai') is None else round(r['ai'],2)}  page={r.get('page')}  {r['input'][:90]}" for r in miss[:40]]
    lines += ["", f"LEGITIMATE FLAGGED (score >= 35): {len(fps)}"]
    lines += [f"  {r['score']:>3}  ai={r.get('ai') if r.get('ai') is None else round(r['ai'],2)}  {r['input'][:70]}  <- {'; '.join(r.get('top_evidence', [])[:3])}" for r in fps[:40]]
    if errs:
        lines += ["", f"SCAN ERRORS: {len(errs)} (first 5)"] + [f"  {r['input'][:70]}  {r['error']}" for r in errs[:5]]
    txt = "\n".join(lines)
    (EVAL / ("report.txt" if RESULTS.name == "results.jsonl" else RESULTS.stem + "_report.txt")).write_text(txt, encoding="utf-8")
    print("\n" + txt + f"\n\n[saved] results: {RESULTS}")


# --------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=200, help="URLs per class")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--conc", type=int, default=4, help="parallel scans (3-4 is gentle on a laptop)")
    ap.add_argument("--no-deep", action="store_true", help="skip live page/domain checks (fast smoke test)")
    ap.add_argument("--phish-file", help="use your own phishing URL list instead of fetching OpenPhish")
    ap.add_argument("--legit-file", help="use your own legitimate URL/domain list instead of Tranco 500k-1M")
    ap.add_argument("--reuse-from", help="re-scan the exact same URLs (and labels) saved in an earlier results.jsonl, "
                    "to compare before/after a code change on identical data")
    ap.add_argument("--out", default="results.jsonl", help="results file name inside data/eval/")
    ap.add_argument("--report-only", action="store_true")
    ap.add_argument("--fresh", action="store_true", help="delete saved results first")
    a = ap.parse_args()
    deep = not a.no_deep

    global RESULTS
    EVAL.mkdir(parents=True, exist_ok=True)
    RESULTS = EVAL / a.out
    if a.fresh and RESULTS.exists():
        RESULTS.unlink()
    if a.report_only:
        return report(deep)

    if a.reuse_from:
        old = [json.loads(l) for l in Path(a.reuse_from).read_text(encoding="utf-8").splitlines() if l.strip()]
        items = [(d["input"], d["label"]) for d in old]
        print(f"[reuse] {len(items)} URLs taken from {a.reuse_from}")
        try:
            asyncio.run(scan_all(items, deep, a.conc))
        except KeyboardInterrupt:
            print("\n[stopped] progress is saved; run again to resume")
        return report(deep)

    exclude = _training_hosts()
    print(f"[exclude] {len(exclude)} hosts seen in training data are skipped")
    ph = read_list(a.phish_file)[: a.n] if a.phish_file else fresh_phishing(a.n, a.seed, exclude)
    lg = read_list(a.legit_file)[: a.n] if a.legit_file else unseen_legit(a.n, a.seed, exclude)
    items = [(u, 1) for u in ph] + [(u, 0) for u in lg]
    random.Random(a.seed).shuffle(items)                      # interleave so a stop halfway stays balanced

    try:
        asyncio.run(scan_all(items, deep, a.conc))
    except KeyboardInterrupt:
        print("\n[stopped] progress is saved; run again to resume")
    report(deep)


if __name__ == "__main__":
    main()
