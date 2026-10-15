#!/usr/bin/env python
"""Train the page-content AI model from data/pages/*.jsonl (made by tools/collect_pages.py).

    python tools/train_page_model.py

Honest evaluation
  * the held-out test set contains only registered domains that never appear in training
    (GroupShuffleSplit), and any test page whose title+opening text also appears in training is removed
    (phishing kits copy one page many times, which would otherwise leak);
  * three variants are compared on that held-out set: text only, structure only, and both;
    the best by PR-AUC is deployed, after probability calibration on a separate calibration split;
  * metrics.json-style output goes to models/page_metrics.json.

State in the report: the classes come from different sources (live phishing feeds vs ranked popular
sites), so these numbers describe this dataset, not the real world. The real test is
tools/evaluate_system.py on URLs collected afterwards.
"""
from __future__ import annotations

import argparse
import glob
import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
from phishguard.page_model import NUMERIC  # noqa: E402


def load(pattern):
    rows = []
    for f in glob.glob(pattern):
        for line in Path(f).read_text(encoding="utf-8").splitlines():
            try:
                d = json.loads(line)
            except Exception:
                continue
            if d.get("skip"):
                continue
            rows.append({"url": d["url"], "label": d["label"], "reg": d["reg"], "hash": d["hash"],
                         "blob": d["blob"], **d["feats"]})
    return pd.DataFrame(rows).drop_duplicates("url").reset_index(drop=True)


def _logit(p):
    p = np.clip(p, 1e-6, 1 - 1e-6)
    return np.log(p / (1 - p)).reshape(-1, 1)


def ece(y, p, bins=10):
    edges = np.linspace(0, 1, bins + 1)
    out = 0.0
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (p >= lo) & (p < hi if hi < 1 else p <= hi)
        if m.any():
            out += m.mean() * abs(y[m].mean() - p[m].mean())
    return float(out)


def metrics(y, p, thr=0.5):
    pred = p >= thr
    tp = int(((y == 1) & pred).sum()); fn = int(((y == 1) & ~pred).sum())
    fp = int(((y == 0) & pred).sum()); tn = int(((y == 0) & ~pred).sum())
    return {"acc": (tp + tn) / len(y), "precision": tp / max(tp + fp, 1), "recall": tp / max(tp + fn, 1),
            "fpr": fp / max(fp + tn, 1), "fnr": fn / max(tp + fn, 1),
            "pr_auc": float(average_precision_score(y, p)), "roc_auc": float(roc_auc_score(y, p)),
            "brier": float(np.mean((p - y) ** 2)), "ece": ece(y, p), "n": int(len(y)), "pos": int(y.sum())}


def make(kind):
    parts = []
    if kind in ("text", "both"):
        parts.append(("word", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=3, max_df=0.6,
                                              max_features=80_000, sublinear_tf=True), "blob"))
    if kind in ("structure", "both"):
        parts.append(("num", StandardScaler(), NUMERIC))
    return Pipeline([("prep", ColumnTransformer(parts)),
                     ("clf", LogisticRegression(C=1.0, max_iter=3000, class_weight="balanced", solver="liblinear"))])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(HERE / "data" / "pages" / "*.jsonl"))
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()

    df = load(a.data)
    if df.empty or df["label"].nunique() < 2:
        sys.exit("[data] need pages of both classes; run tools/collect_pages.py first")
    y = df["label"].to_numpy()
    print(f"[data] {len(df)} pages | phishing={int(y.sum())} legit={int((1 - y).sum())} | domains={df['reg'].nunique()}")

    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=a.seed)
    tr_idx, te_idx = next(gss.split(df, y, groups=df["reg"]))
    train_hashes = set(df.loc[tr_idx, "hash"])
    te_idx = np.array([i for i in te_idx if df.loc[i, "hash"] not in train_hashes])             # kit copies
    g2 = GroupShuffleSplit(n_splits=1, test_size=0.15, random_state=a.seed + 1)
    fit_rel, cal_rel = next(g2.split(df.iloc[tr_idx], y[tr_idx], groups=df.iloc[tr_idx]["reg"]))
    fit_idx, cal_idx = tr_idx[fit_rel], tr_idx[cal_rel]
    print(f"[split] fit={len(fit_idx)} calibration={len(cal_idx)} test={len(te_idx)} (test domains unseen, kit copies removed)")

    results, fitted, cals = {}, {}, {}
    for kind in ("text", "structure", "both"):
        pipe = make(kind).fit(df.iloc[fit_idx], y[fit_idx])
        raw_cal = pipe.predict_proba(df.iloc[cal_idx])[:, 1]
        cal = LogisticRegression(C=1e4, max_iter=1000).fit(_logit(raw_cal), y[cal_idx])
        raw = pipe.predict_proba(df.iloc[te_idx])[:, 1]
        p = cal.predict_proba(_logit(raw))[:, 1]
        m = metrics(y[te_idx], p)
        m["uncalibrated_ece"] = ece(y[te_idx], raw)
        results[kind], fitted[kind], cals[kind] = m, pipe, cal
        print(f"[{kind}] acc={m['acc']:.4f} prec={m['precision']:.4f} rec={m['recall']:.4f} fpr={m['fpr']:.4f} "
              f"pr_auc={m['pr_auc']:.4f} roc_auc={m['roc_auc']:.4f} | ECE {m['uncalibrated_ece']:.3f} -> {m['ece']:.3f}")
    best = max(results, key=lambda k: results[k]["pr_auc"])
    print(f"[select] best on held-out domains by PR-AUC: {best}")

    out = HERE / "models"
    out.mkdir(exist_ok=True)
    bundle = {"pipeline": fitted[best], "calibrator": cals[best], "variant": best,
              "trained_on": f"{len(df)} live pages ({int(y.sum())} phishing, {int((1 - y).sum())} legitimate), "
                            f"collected {time.strftime('%Y-%m-%d')}",
              "version": "1"}
    joblib.dump(bundle, out / "page_model.joblib")
    (out / "page_metrics.json").write_text(json.dumps({
        "selected": best, "candidates": results, "n_pages": int(len(df)), "n_phishing": int(y.sum()),
        "n_domains": int(df["reg"].nunique()),
        "note": "Held-out = unseen registered domains, kit copies removed. Classes come from different "
                "sources; real-world accuracy is measured separately by tools/evaluate_system.py."}, indent=2))
    print(f"[saved] {out / 'page_model.joblib'}")


if __name__ == "__main__":
    main()
