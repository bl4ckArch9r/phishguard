#!/usr/bin/env python
"""Train the PhishGuard URL classifier on a labelled CSV of raw URLs.

    python train.py --data data/urls.csv

Accepted CSV layouts (auto-detected, override with --url-col / --label-col):
    url,label            label: 1/0, phishing/legitimate, bad/good, malicious/benign
    URL,Label            (Kaggle "Phishing Site URLs": bad/good)
    url,type             (Kaggle "Malicious URLs": benign/phishing/...; others dropped)

Evaluation is done two ways on purpose:
  * domain-held-out split  - no registered domain appears in both train and test
                             (the honest, harder number; this is what we report)
  * random split           - the optimistic number many papers report
The gap between them shows how much a model memorises domains.
"""
import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, brier_score_loss, confusion_matrix,
                             f1_score, precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).parent))
from phishguard import features as F  # noqa: E402

URL_COLS = ["url", "URL", "Url", "link", "Link", "website"]
LABEL_COLS = ["label", "Label", "type", "Type", "class", "Class", "result", "Result", "status"]
POS = {"bad", "phishing", "phish", "malicious", "fraud", "spam", "1", "1.0", "true", "yes"}
NEG = {"good", "benign", "legitimate", "legit", "safe", "0", "0.0", "false", "no"}


def load(path, url_col, label_col, max_rows, seed):
    df = pd.read_csv(path)
    url_col = url_col or next((c for c in URL_COLS if c in df.columns), None)
    label_col = label_col or next((c for c in LABEL_COLS if c in df.columns), None)
    if not url_col or not label_col:
        sys.exit(f"Could not find url/label columns in {list(df.columns)}. Use --url-col/--label-col.")
    df = df[[url_col, label_col]].rename(columns={url_col: "url", label_col: "label_raw"})
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"].str.len() > 3].drop_duplicates("url")
    norm = df["label_raw"].astype(str).str.strip().str.lower()
    df["label"] = np.where(norm.isin(POS), 1, np.where(norm.isin(NEG), 0, -1))
    dropped = int((df["label"] == -1).sum())
    df = df[df["label"] != -1].copy()
    if dropped:
        print(f"[data] dropped {dropped} rows with labels that are neither phishing nor legitimate")
    if max_rows and len(df) > max_rows:
        df, _ = train_test_split(df, train_size=max_rows, stratify=df["label"], random_state=seed)
    return df.reset_index(drop=True)


def add_root_forms(df, frac, seed):
    """Add a host-only copy (scheme and path removed) of a share of URLs, same label.

    In many datasets legitimate URLs are deep pages while phishing URLs are often
    bare domains, so 'has no path' becomes a shortcut for 'phishing' and a real
    homepage such as wikipedia.org gets flagged. Showing the model both classes
    in host-only form removes that shortcut. Copies share the original's domain,
    so the domain-held-out split stays leak-free."""
    from urllib.parse import urlsplit
    if frac <= 0:
        return df
    pick = df.sample(frac=min(frac, 1.0), random_state=seed)
    hosts = []
    for u in pick["url"]:
        try:
            p = urlsplit(F.normalize_url(u))
            has_path = (p.path not in ("", "/")) or p.query
            hosts.append(p.netloc if has_path and p.netloc else None)
        except ValueError:          # malformed URL in the dataset: skip it
            hosts.append(None)
    pick = pick.assign(url=hosts).dropna(subset=["url"])
    out = pd.concat([df, pick[["url", "label_raw", "label"]]], ignore_index=True)
    out = out.drop_duplicates("url").reset_index(drop=True)
    print(f"[data] added {len(out) - len(df)} host-only copies (shortcut removal)")
    return out


def build_features(df):
    t0 = time.time()
    rows = [F.extract(u) for u in df["url"]]
    X = pd.DataFrame(rows)
    X["url"] = df["url"].map(F.model_text).values
    print(f"[features] {len(X)} URLs in {time.time()-t0:.1f}s")
    return X


def make_models(numeric):
    lr = Pipeline([
        ("prep", ColumnTransformer([
            ("char", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=3,
                                     max_features=150_000, sublinear_tf=True), "url"),
            ("num", StandardScaler(), numeric),
        ])),
        ("clf", LogisticRegression(C=2.0, max_iter=2000, class_weight="balanced", solver="liblinear")),
    ])
    rf = Pipeline([
        ("prep", ColumnTransformer([("num", "passthrough", numeric)])),
        ("clf", RandomForestClassifier(n_estimators=300, min_samples_leaf=2, n_jobs=-1,
                                       class_weight="balanced_subsample", random_state=42)),
    ])
    return {"logistic_regression_char_ngrams": lr, "random_forest_lexical": rf}


def expected_calibration_error(y_true, prob, bins=10):
    """Average gap between predicted probability and observed frequency (0 = perfectly calibrated)."""
    y_true = np.asarray(y_true); prob = np.asarray(prob)
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(prob, edges[1:-1]), 0, bins - 1)
    ece = 0.0
    for b in range(bins):
        m = idx == b
        if m.any():
            ece += m.mean() * abs(prob[m].mean() - y_true[m].mean())
    return float(ece)


def _logit(p):
    p = np.clip(np.asarray(p, dtype=float), 1e-6, 1 - 1e-6)
    return np.log(p / (1 - p)).reshape(-1, 1)


def metrics(y_true, prob, thr=0.5):
    pred = (prob >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    return {
        "accuracy": accuracy_score(y_true, pred),
        "precision": precision_score(y_true, pred, zero_division=0),
        "recall": recall_score(y_true, pred, zero_division=0),
        "f1": f1_score(y_true, pred, zero_division=0),
        "false_positive_rate": fp / max(fp + tn, 1),
        "false_negative_rate": fn / max(fn + tp, 1),
        "roc_auc": roc_auc_score(y_true, prob) if len(set(y_true)) > 1 else None,
        "pr_auc": average_precision_score(y_true, prob) if len(set(y_true)) > 1 else None,
        "brier": brier_score_loss(y_true, prob),
        "ece": expected_calibration_error(y_true, prob),
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "threshold": thr,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--url-col"); ap.add_argument("--label-col")
    ap.add_argument("--max-rows", type=int, default=250_000)
    ap.add_argument("--out", default=str(Path(__file__).parent / "models"))
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--root-frac", type=float, default=0.4,
                    help="share of URLs that also get a host-only copy (0 disables)")
    a = ap.parse_args()

    df = load(a.data, a.url_col, a.label_col, a.max_rows, a.seed)
    df = add_root_forms(df, a.root_frac, a.seed)
    print(f"[data] {len(df)} unique URLs | phishing={int(df.label.sum())} legit={int((df.label==0).sum())}")
    X = build_features(df)
    y = df["label"].values
    groups = df["url"].map(lambda u: F.registered_domain(F.normalize_url(u).split("//", 1)[-1].split("/")[0].split(":")[0])).values
    # The scheme says how the dataset was collected, not whether a site is malicious (in many datasets
    # phishing URLs carry an explicit https:// and legitimate ones do not), so the model never sees it.
    # The https check still exists as a plain rule in pipeline.py.
    numeric = [c for c in F.FEATURE_NAMES if c != "is_https"]

    # --- domain-held-out split (primary) -------------------------------
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=a.seed)
    tr, te = next(gss.split(X, y, groups))
    print(f"[split] domain-held-out: train={len(tr)} test={len(te)} | overlap domains="
          f"{len(set(groups[tr]) & set(groups[te]))}")

    # Part of the training domains is set aside to calibrate probabilities (never used to fit or test).
    gss2 = GroupShuffleSplit(n_splits=1, test_size=0.15, random_state=a.seed + 1)
    fi, ci = next(gss2.split(X.iloc[tr], y[tr], groups[tr]))
    fit_idx, cal_idx = tr[fi], tr[ci]
    print(f"[split] fit={len(fit_idx)} calibration={len(cal_idx)} test={len(te)}")

    results, fitted, calibrators, raw_results = {}, {}, {}, {}
    for name, pipe in make_models(numeric).items():
        t0 = time.time()
        pipe.fit(X.iloc[fit_idx], y[fit_idx])
        raw_te = pipe.predict_proba(X.iloc[te])[:, 1]
        raw_cal = pipe.predict_proba(X.iloc[cal_idx])[:, 1]
        cal = LogisticRegression(C=1e4, max_iter=1000).fit(_logit(raw_cal), y[cal_idx])     # Platt scaling
        prob = cal.predict_proba(_logit(raw_te))[:, 1]
        raw_results[name] = metrics(y[te], raw_te)
        results[name] = metrics(y[te], prob)
        results[name]["train_seconds"] = round(time.time() - t0, 1)
        fitted[name], calibrators[name] = pipe, cal
        m, rm = results[name], raw_results[name]
        print(f"[{name}] acc={m['accuracy']:.4f} prec={m['precision']:.4f} rec={m['recall']:.4f} "
              f"f1={m['f1']:.4f} fpr={m['false_positive_rate']:.4f} fnr={m['false_negative_rate']:.4f} "
              f"pr_auc={m['pr_auc']:.4f} | calibration ECE {rm['ece']:.3f} -> {m['ece']:.3f}, Brier {rm['brier']:.3f} -> {m['brier']:.3f}")

    best = max(results, key=lambda k: results[k]["pr_auc"])
    print(f"[select] best on held-out domains by PR-AUC (threshold-free): {best}")

    # --- optimism check: same model on a random split -------------------
    rtr, rte = train_test_split(np.arange(len(X)), test_size=0.2, stratify=y, random_state=a.seed)
    chk = make_models(numeric)[best]
    chk.fit(X.iloc[rtr], y[rtr])
    rand_m = metrics(y[rte], chk.predict_proba(X.iloc[rte])[:, 1])
    held_m = raw_results[best]
    print(f"[optimism] random-split pr_auc={rand_m['pr_auc']:.4f} vs domain-held-out pr_auc={held_m['pr_auc']:.4f} "
          f"(f1 {rand_m['f1']:.4f} vs {held_m['f1']:.4f}, uncalibrated)")

    # --- inference time (feature extraction + prediction, single URL) ---
    sample = df["url"].sample(min(300, len(df)), random_state=1).tolist()
    pipe = fitted[best]
    t0 = time.perf_counter()
    for u in sample:
        row = F.extract(u); row["url"] = F.model_text(u)
        pipe.predict_proba(pd.DataFrame([row]))
    ms = (time.perf_counter() - t0) / len(sample) * 1000

    # --- deploy the model that was evaluated, with its calibrator -------------
    final = fitted[best]
    clf = final.named_steps["clf"]
    imps = {}
    if hasattr(clf, "feature_importances_"):
        imps = dict(zip(numeric, map(float, clf.feature_importances_)))
    Xfit = X.iloc[fit_idx]
    stats = {c: {"mean": float(Xfit[c].mean()), "std": float(Xfit[c].std() or 1.0)} for c in numeric}

    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    bundle = {
        "pipeline": final, "model_name": best, "numeric_cols": numeric,
        "numeric_stats": stats, "importances": imps, "calibrator": calibrators[best],
        "trained_on": Path(a.data).name, "version": datetime.now(timezone.utc).strftime("%Y%m%d%H%M"),
    }
    joblib.dump(bundle, out / "phishing_model.joblib", compress=3)

    report = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "data_file": Path(a.data).name,
        "n_urls": int(len(df)), "n_phishing": int(y.sum()), "n_legit": int((y == 0).sum()),
        "evaluation": "domain-held-out 80/20 (no registered domain in both sets)",
        "candidates": results, "selected": best,
        "selected_metrics": results[best],
        "uncalibrated_metrics_for_selected": raw_results[best],
        "random_split_metrics_for_selected": rand_m,
        "generalization_gap_f1": round(rand_m["f1"] - raw_results[best]["f1"], 4),
        "generalization_gap_pr_auc": round(rand_m["pr_auc"] - raw_results[best]["pr_auc"], 4),
        "calibration": "Platt scaling fitted on a separate set of training domains; metrics above use calibrated probabilities at threshold 0.5",
        "inference_ms_per_url": round(ms, 2),
        "note": "Metrics are measured on the file named in data_file. They describe that dataset, not real-world performance.",
    }
    (out / "metrics.json").write_text(json.dumps(report, indent=2))
    print(f"[saved] {out/'phishing_model.joblib'}  |  {out/'metrics.json'}  | {ms:.2f} ms/URL")


if __name__ == "__main__":
    main()
