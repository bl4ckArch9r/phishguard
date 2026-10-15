"""Loads the trained URL model and explains each prediction.

Explanation method
  * Logistic regression: exact contribution = coefficient x scaled feature value.
  * Random forest: approximate contribution = feature importance x z-score
    (clearly marked as approximate in the output).
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from . import features as F

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"


# Explanation sentences describe a feature being HIGH, except these, which are risky when LOW.
RISKY_WHEN_LOW = {"is_https"}


class UrlModel:
    def __init__(self, bundle: dict):
        self.bundle = bundle
        self.pipeline = bundle["pipeline"]
        self.calibrator = bundle.get("calibrator")
        self.name = bundle["model_name"]
        self.numeric = bundle["numeric_cols"]
        self.stats = bundle["numeric_stats"]            # mean/std from training data
        self.importances = bundle.get("importances", {})
        self.trained_on = bundle.get("trained_on", "unknown")
        self.version = bundle.get("version", "1")

    # ------------------------------------------------------------------
    @classmethod
    def load(cls, path: Path | None = None):
        path = path or (MODELS_DIR / "phishing_model.joblib")
        if not Path(path).exists():
            return None
        return cls(joblib.load(path))

    def _risky_side(self, key: str, value: float) -> bool:
        """True only if the value is on the side the explanation sentence describes."""
        st = self.stats.get(key, {"mean": 0, "std": 1})
        z = (value - st["mean"]) / (st["std"] or 1.0)
        return z <= -0.9 if key in RISKY_WHEN_LOW else z >= 0.9   # clearly unusual, not just above average

    def _frame(self, url: str) -> pd.DataFrame:
        url = F.normalize_url(url)
        row = F.extract(url)
        row["url"] = F.model_text(url)
        return pd.DataFrame([row])

    # ------------------------------------------------------------------
    def predict(self, url: str) -> dict:
        t0 = time.perf_counter()
        df = self._frame(url)
        prob = float(self.pipeline.predict_proba(df)[0][1])
        if self.calibrator is not None:                       # turn the raw score into a real probability
            z = np.log(np.clip(prob, 1e-6, 1 - 1e-6) / (1 - np.clip(prob, 1e-6, 1 - 1e-6)))
            prob = float(self.calibrator.predict_proba(np.array([[z]]))[0][1])
        feats = df.iloc[0][self.numeric].astype(float).to_dict()
        contributions = self._contributions(df, feats)
        return {
            "probability": prob,
            "model": self.name,
            "trained_on": self.trained_on,
            "features": feats,
            "contributions": contributions,
            "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
        }

    # ------------------------------------------------------------------
    def _contributions(self, df: pd.DataFrame, feats: dict) -> dict:
        out = {"method": "exact", "numeric": [], "patterns": []}
        clf = self.pipeline.named_steps["clf"]
        prep = self.pipeline.named_steps["prep"]

        if hasattr(clf, "coef_"):  # logistic regression
            Xt = prep.transform(df)
            coefs = clf.coef_[0]
            names = list(prep.get_feature_names_out())
            row = Xt.toarray()[0] if hasattr(Xt, "toarray") else np.asarray(Xt)[0]
            contrib = coefs * row
            for i in np.argsort(-contrib)[:40]:
                if contrib[i] <= 0:
                    break
                n = names[i]
                if n.startswith("num__"):
                    key = n[5:]
                    if not self._risky_side(key, feats.get(key, 0)):
                        continue  # model leaned on the feature being LOW; don't describe it as a warning sign
                    out["numeric"].append({"feature": key, "text": F.FEATURE_TEXT.get(key, key), "value": feats.get(key), "weight": float(contrib[i])})
                elif n.startswith("char__"):
                    out["patterns"].append({"pattern": n[6:], "weight": float(contrib[i])})
            out["numeric"] = out["numeric"][:6]
            out["patterns"] = out["patterns"][:5]
        else:  # tree model: approximate
            out["method"] = "approximate"
            items = []
            for k, v in feats.items():
                s = self.stats.get(k, {"mean": 0, "std": 1})
                z = (v - s["mean"]) / (s["std"] or 1.0)
                if k in RISKY_WHEN_LOW:
                    z = -z
                w = self.importances.get(k, 0.0) * max(z, 0.0) if z >= 0.9 else 0.0
                if w > 0:
                    items.append({"feature": k, "text": F.FEATURE_TEXT.get(k, k), "value": v, "weight": float(w)})
            out["numeric"] = sorted(items, key=lambda d: -d["weight"])[:6]
        return out


def load_metrics() -> dict | None:
    p = MODELS_DIR / "metrics.json"
    if p.exists():
        return json.loads(p.read_text())
    return None
