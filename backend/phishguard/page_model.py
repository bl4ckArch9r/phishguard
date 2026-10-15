"""Second AI model: reads the CONTENT of a page (what it says and how it is built), not the address.

The URL model cannot see a page. A free-hosted clone of a login page can have a harmless-looking
address, but its title, wording, form fields and structure give it away. This model turns a page into
  * a text blob  (title, headings, input labels, button/link text, visible text), and
  * structure numbers (forms, password fields, where the form posts, link/script/iframe mix, ...)
and scores it with a calibrated logistic regression (word TF-IDF + scaled numbers).

Training data and evaluation are described in tools/collect_pages.py and tools/train_page_model.py.
The same extractor is used for training and for scoring, so the two cannot drift apart.
"""
from __future__ import annotations

import math
import re
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
from bs4 import BeautifulSoup

from . import features as F
from .brands import BRANDS, PAGE_BRANDS

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
PAGE_MODEL_PATH = MODELS_DIR / "page_model.joblib"

NUMERIC = [
    "n_forms", "n_inputs", "n_password", "n_hidden", "n_text_inputs", "form_external", "form_empty_action",
    "n_links", "ext_link_ratio", "n_iframes", "n_scripts", "ext_script_ratio", "log_text_len", "title_len",
    "n_images", "meta_refresh", "log_inline_js", "brand_title_mismatch", "n_buttons", "has_title",
]

_MARKERS = {"title", "head", "meta", "inputs", "buttons", "links", "text"}
_ALL_BRANDS = {**BRANDS, **PAGE_BRANDS}
_WS = re.compile(r"\s+")


def _reg(url: str) -> str:
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        host = ""
    return F.registered_domain(host) if host else ""


def extract(final_url: str, html: str) -> tuple[str, dict]:
    """Returns (text blob, numeric features) for one page."""
    soup = BeautifulSoup(html or "", "html.parser")
    page_reg = _reg(final_url)

    title = _WS.sub(" ", (soup.title.string or "") if soup.title and soup.title.string else "").strip()
    heads = " ".join(h.get_text(" ", strip=True) for h in soup.find_all(["h1", "h2", "h3"])[:8])
    metas = " ".join((m.get("content") or "") for m in soup.find_all("meta")
                     if (m.get("name") or m.get("property") or "").lower() in ("description", "og:title", "og:description", "og:site_name"))

    inputs = soup.find_all("input")
    labels = []
    for i in inputs[:40]:
        labels.append(" ".join(filter(None, [i.get("type"), i.get("name"), i.get("placeholder"), i.get("aria-label"), i.get("autocomplete")])))
    buttons = soup.find_all(["button"]) + [i for i in inputs if (i.get("type") or "").lower() in ("submit", "button")]
    btn_text = " ".join((b.get_text(" ", strip=True) or b.get("value") or "") for b in buttons[:15])
    link_text = " ".join(a.get_text(" ", strip=True) for a in soup.find_all("a")[:25])

    for t in soup(["script", "style", "noscript"]):
        t.extract()
    visible = _WS.sub(" ", soup.get_text(" ", strip=True))
    text_len = len(visible)

    forms = soup.find_all("form")
    form_external = form_empty = 0
    for f in forms:
        act = (f.get("action") or "").strip()
        if not act or act.startswith("#") or act.lower().startswith("javascript"):
            form_empty += 1
        elif act.startswith("http"):
            if _reg(act) != page_reg:
                form_external += 1

    types = [(i.get("type") or "text").lower() for i in inputs]
    links = [a.get("href") or "" for a in soup.find_all("a")]
    ext_links = sum(1 for h in links if h.startswith("http") and _reg(h) != page_reg)
    scripts_all = BeautifulSoup(html or "", "html.parser").find_all("script")
    src = [s.get("src") for s in scripts_all if s.get("src")]
    ext_src = sum(1 for s in src if s.startswith("http") and _reg(s) != page_reg)
    inline_js = sum(len(s.get_text()) for s in scripts_all if not s.get("src"))

    head = title.lower()
    mism = 0
    for _b, cfg in _ALL_BRANDS.items():
        if page_reg in cfg["official"]:
            continue
        if any(re.match(re.escape(k) + r"\b", head) for k in cfg["keywords"]):
            mism = 1
            break

    meta_refresh = 1 if BeautifulSoup(html or "", "html.parser").find("meta", attrs={"http-equiv": re.compile("refresh", re.I)}) else 0

    feats = {
        "n_forms": min(len(forms), 10), "n_inputs": min(len(inputs), 40),
        "n_password": min(types.count("password"), 5), "n_hidden": min(types.count("hidden"), 40),
        "n_text_inputs": min(sum(t in ("text", "email", "tel", "number") for t in types), 20),
        "form_external": min(form_external, 5), "form_empty_action": min(form_empty, 5),
        "n_links": min(len(links), 200), "ext_link_ratio": (ext_links / len(links)) if links else 0.0,
        "n_iframes": min(len(soup.find_all("iframe")), 10), "n_scripts": min(len(scripts_all), 50),
        "ext_script_ratio": (ext_src / len(src)) if src else 0.0,
        "log_text_len": math.log1p(text_len), "title_len": min(len(title), 200),
        "n_images": min(len(soup.find_all("img")), 100), "meta_refresh": meta_refresh,
        "log_inline_js": math.log1p(inline_js), "brand_title_mismatch": mism,
        "n_buttons": min(len(buttons), 20), "has_title": 1 if title else 0,
    }
    blob = " | ".join([
        "TITLE " + title, "HEAD " + heads[:400], "META " + metas[:400], "INPUTS " + " ; ".join(labels)[:600],
        "BUTTONS " + btn_text[:300], "LINKS " + link_text[:500], "TEXT " + visible[:2500],
    ])
    return blob.lower(), feats


class PageModel:
    def __init__(self, bundle: dict):
        self.bundle = bundle
        self.pipeline = bundle["pipeline"]
        self.calibrator = bundle.get("calibrator")
        self.trained_on = bundle.get("trained_on", "unknown")
        self.version = bundle.get("version", "1")

    @classmethod
    def load(cls, path: Path | None = None):
        path = Path(path or PAGE_MODEL_PATH)
        if not path.exists():
            return None
        return cls(joblib.load(path))

    def predict(self, final_url: str, html: str) -> dict:
        blob, feats = extract(final_url, html)
        df = pd.DataFrame([{**feats, "blob": blob}])
        prob = float(self.pipeline.predict_proba(df)[0][1])
        if self.calibrator is not None:
            p = min(max(prob, 1e-6), 1 - 1e-6)
            prob = float(self.calibrator.predict_proba(np.array([[math.log(p / (1 - p))]]))[0][1])
        return {"probability": prob, "terms": self._terms(df), "features": feats}

    def _terms(self, df) -> list[str]:
        try:
            prep = self.pipeline.named_steps["prep"]
            clf = self.pipeline.named_steps["clf"]
            X = prep.transform(df)
            row = X.toarray()[0] if hasattr(X, "toarray") else np.asarray(X)[0]
            names = prep.get_feature_names_out()
            contrib = clf.coef_[0] * row
            out = []
            for i in np.argsort(-contrib)[:12]:
                if contrib[i] <= 0:
                    break
                n = names[i]
                if n.startswith("word__"):
                    term = n[6:]
                    # section markers (TITLE, HEAD, META, INPUTS, BUTTONS, LINKS, TEXT) are labels we add, not page words
                    if all(tok in _MARKERS for tok in term.split()):
                        continue
                    out.append(term)
            return out[:6]
        except Exception:
            return []
