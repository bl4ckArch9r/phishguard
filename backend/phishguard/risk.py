"""Risk correlation: turns the model probability and all evidence into one
transparent 0-100 score.

    score = model_points + capped evidence points (per layer)
    (the URL-rule cap is 15 while the model is present, because the model already
     reads the same URL features; it rises to 40 when no model is loaded)
    threat-feed hit      -> floor of 92
    official brand domain with no feed hit -> cap of 12

Every number below is a named constant so the weighting can be tuned against
the evaluation set (the proposal says weights are decided by experiment, not
fixed arbitrarily). Verdict bands:  < 35 Safe,  35-64 Suspicious,  >= 65 Phishing.
"""
from __future__ import annotations

import os
from pathlib import Path

from .brands import official_domains
from .evidence import Evidence

ESTABLISHED_FACTOR = 0.4   # valid cert + clean page + domain registered >= 1 year ago
CLEAN_LIVE_FACTOR = 0.7    # valid cert + clean page, domain age unknown (many ccTLDs have no RDAP)
TOP_SITE_CAP = 20          # a well-known site's own homepage can't look phishing from the URL alone
TOP_DOMAINS_FILE = Path(os.environ.get("PHISHGUARD_TOP_DOMAINS") or
                        Path(__file__).resolve().parent.parent / "data" / "top_domains.txt")
_top = {"mtime": None, "domains": frozenset()}


def top_domains() -> frozenset:
    """Popular registered domains (Tranco top list). Fetch with: python tools/fetch_top_domains.py"""
    try:
        m = TOP_DOMAINS_FILE.stat().st_mtime
    except OSError:
        _top.update(mtime=None, domains=frozenset())
        return _top["domains"]
    if _top["mtime"] != m:
        lines = TOP_DOMAINS_FILE.read_text(errors="ignore").split()
        _top.update(mtime=m, domains=frozenset(x.strip().lower() for x in lines if x.strip()))
    return _top["domains"]

MODEL_MAX_POINTS = 55
LAYER_CAPS = {"url": 15, "brand": 40, "page": 55, "domain": 30, "intel": 100, "pageai": 30}
URL_CAP_NO_MODEL = 40     # with no AI model, URL rules are the only URL-structure signal
SAFE_BELOW = 35
PHISHING_AT = 65
FEED_FLOOR = 92
HOST_FLAG_FLOOR = 75          # the hosting provider itself shows a malware/phishing warning page
OFFICIAL_CAP = 12


def verdict_for(score: int) -> str:
    if score >= PHISHING_AT:
        return "phishing"
    if score >= SAFE_BELOW:
        return "suspicious"
    return "safe"


def correlate(model_prob: float | None, evidence: list[Evidence], reg_domain: str,
              layers_available: dict, host: str = "", facts: dict | None = None) -> dict:
    breakdown = {}
    model_points = round((model_prob or 0.0) * MODEL_MAX_POINTS)
    notes = []

    # The model reads only the address. When the live checks positively look legitimate
    # (trusted certificate, page inspected, nothing suspicious anywhere else) its weight is reduced.
    dom = (facts or {}).get("domain", {})
    live_clean = (model_prob is not None and dom.get("tls") == "valid" and layers_available.get("page")
                  and not any(e.points > 0 for e in evidence if e.layer in ("page", "domain", "brand", "intel", "pageai")))
    if live_clean and model_points:
        age = dom.get("domain_age_days")
        factor = ESTABLISHED_FACTOR if (age is not None and age >= 365) else CLEAN_LIVE_FACTOR
        model_points = round(model_points * factor)
        notes.append("The live checks found a trusted certificate and no suspicious page behaviour"
                     + (", on a domain registered over a year ago" if factor == ESTABLISHED_FACTOR else "")
                     + ", so the address-only AI score was given less weight.")
    breakdown["model"] = model_points

    total = model_points
    caps = dict(LAYER_CAPS)
    if model_prob is None:        # model absent: don't throttle the rules that cover the same ground
        caps["url"] = URL_CAP_NO_MODEL
    for layer, cap in caps.items():
        pts = sum(e.points for e in evidence if e.layer == layer)
        pts = min(pts, cap)
        if pts:
            breakdown[layer] = pts
        total += pts

    feed_hit = any(e.layer == "intel" and e.severity == "critical" for e in evidence)
    host_flag = any(e.id == "host_flagged" for e in evidence)
    if feed_hit:
        total = max(total, FEED_FLOOR)
        notes.append("A threat-intelligence source lists this URL, which sets a high minimum score.")
    elif host_flag:
        total = max(total, HOST_FLAG_FLOOR)
        notes.append("The hosting provider is showing its own malware/phishing warning for this site, "
                     "which sets a high minimum score.")
    elif reg_domain in official_domains():
        total = min(total, OFFICIAL_CAP)
        notes.append("This is a recognised official domain, so the score is capped low.")
    elif (host in (reg_domain, "www." + reg_domain) and reg_domain in top_domains()
          and not any(e.layer in ("page", "domain", "brand") and e.severity in ("high", "critical")
                      for e in evidence)):
        # Only the bare domain / www host: attackers can't own a top-site domain, but they can
        # create subdomains on shared platforms, so those are never capped.
        if total > TOP_SITE_CAP:
            total = TOP_SITE_CAP
            notes.append("This is the main address of a very widely used website, so the address-only "
                         "AI score is capped. Live page checks can still raise it.")

    score = max(0, min(100, int(total)))
    verdict = verdict_for(score)

    # Confidence: how much independent evidence we actually had.
    available = [k for k, v in layers_available.items() if v]
    coverage = len(available) / max(len(layers_available), 1)
    agree = 0
    strong = [e for e in evidence if e.points >= 10]
    if verdict == "safe":
        confidence = 0.55 + 0.4 * coverage - 0.1 * len(strong)
    else:
        confidence = 0.45 + 0.25 * coverage + min(len(strong), 4) * 0.08
    if feed_hit:
        confidence = max(confidence, 0.97)
    elif host_flag:
        confidence = max(confidence, 0.9)
    confidence = max(0.2, min(0.99, confidence))

    if verdict == "safe" and coverage < 0.5:
        notes.append("Several checks could not run, so this 'safe' result is based on limited evidence.")

    return {
        "score": score,
        "verdict": verdict,
        "confidence": round(confidence, 2),
        "breakdown": breakdown,
        "coverage": {"available": available, "total": len(layers_available)},
        "notes": notes,
    }


ACTIONS = {
    "phishing": [
        "Do not enter any password, card number or personal details on this page.",
        "If you already did, change that password immediately and enable two-factor authentication.",
        "Report the link to your IT/security team or the impersonated company.",
    ],
    "suspicious": [
        "Do not log in from this link. Open the company's website by typing its address yourself.",
        "Check who sent you the link and confirm with them through another channel.",
    ],
    "safe": [
        "No strong phishing signals were found, but stay alert if the message asking you to click was unexpected.",
    ],
}
