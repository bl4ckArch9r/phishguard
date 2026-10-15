"""Orchestrates one analysis: URL features -> ML model -> brand checks ->
(live) page + domain + threat intel in parallel -> risk correlation."""
from __future__ import annotations

import asyncio
import re
import time
from urllib.parse import urlsplit

from . import features as F
from .brands import FREE_HOSTS
from . import browser_analyzer, risk, threat_intel
from .domain_intel import brand_in_domain, run_domain_intel, typosquat_check
from .evidence import Evidence
from .model_service import UrlModel
from .page_model import PageModel
from .netguard import safe_fetch
from .page_analyzer import analyze_page

MODEL: UrlModel | None = UrlModel.load()
PAGE_MODEL: PageModel | None = PageModel.load()
PAGEAI_MAX = 30          # most points the page-content AI can add (rises from 0 at p=0.3 to this at p=1)
PAGEAI_START = 0.3


def reload_model():
    global MODEL
    MODEL = UrlModel.load()
    return MODEL


class InvalidURL(ValueError):
    pass


def validate(raw: str) -> str:
    url = F.normalize_url(raw)
    if len(url) > 2048:
        raise InvalidURL("URL is longer than 2048 characters")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise InvalidURL("Only http and https links can be analysed")
    try:
        host = parts.hostname
    except ValueError:
        host = None
    if not host or "." not in host and host != "localhost":
        raise InvalidURL("That doesn't look like a valid web address")
    return url


def _url_evidence(feats: dict) -> list[Evidence]:
    ev = []
    if feats["has_ip_host"]:
        ev.append(Evidence("url", "ip_host", "Address is a raw IP, not a domain name",
                           "Legitimate services almost always use a registered domain.", "high", 20))
        if feats["keyword_hits_path"] >= 1:
            ev.append(Evidence("url", "ip_login", "Login-style page served from a bare IP address",
                               "Real sign-in pages live on a named domain, not a numeric address.", "high", 15))
    if feats["has_at"]:
        ev.append(Evidence("url", "at_symbol", "URL contains '@'",
                           "Everything before '@' is ignored by the browser, which attackers abuse to disguise the destination.",
                           "high", 12))
    if feats["is_shortener"]:
        ev.append(Evidence("url", "shortener", "Link shortener hides the real destination", "", "medium", 6))
    if feats["has_punycode"]:
        ev.append(Evidence("url", "punycode", "Hostname uses punycode",
                           "Can display look-alike characters from other alphabets.", "medium", 8))
    if feats["suspicious_tld"]:
        ev.append(Evidence("url", "bad_tld", "Domain ending commonly abused for scams", "", "low", 4))
    if feats["subdomain_count"] >= 3:
        ev.append(Evidence("url", "deep_subdomain", "Many subdomains before the real domain",
                           "Attackers stack subdomains so a trusted name appears first.", "medium", 6))
    if feats["random_label"]:
        ev.append(Evidence("url", "random_label", "Domain name looks randomly generated",
                           "Auto-generated names are typical of throwaway phishing infrastructure.", "medium", 10))
    kh = feats["keyword_hits_host"]
    if kh >= 3:
        ev.append(Evidence("url", "keyword_stuffing", "Hostname is stuffed with login/verify-style words",
                           f"{kh} sensitive words in one hostname is very rare on real sites and common on scam domains.", "high", 22))
    elif kh == 2:
        ev.append(Evidence("url", "keyword_host", "Hostname contains several login/verify-style words", "", "medium", 14))
    elif kh == 1 and feats["hyphens_in_host"]:
        ev.append(Evidence("url", "keyword_host", "Hostname contains login/verify-style wording", "", "medium", 6))
    if feats["keyword_hits_path"] >= 2 and not feats["has_ip_host"]:
        ev.append(Evidence("url", "keyword_path", "Path is full of login/verify-style words", "", "low", 6))
    if not feats["is_https"]:
        ev.append(Evidence("url", "no_https", "Not using HTTPS",
                           "The connection is not encrypted.", "low", 3))
    if feats["double_slash_in_path"]:
        ev.append(Evidence("url", "double_slash", "Redirect-style '//' inside the path", "", "low", 3))
    return ev


# A page the scanner could not actually read must not count as "inspected and clean":
#  * a network/ISP/company web filter answers with its own block page (found when the evaluation
#    showed 185 of 200 phishing URLs returning "Web Filter Violation" from the test network);
#  * a hosting provider may show its own malware/phishing interstitial, which is strong evidence;
#  * an HTTP 4xx/5xx answer is an error page, not the site.
_HOST_FLAG = ("suspected malware | cloudflare", "suspected phishing | cloudflare",
              "phishing attempt | cloudflare", "deceptive site ahead")
_SUSPENDED = ("access restricted", "접속이 제한", "account suspended", "this account has been suspended",
              "this site has been suspended", "site suspended")
_BLOCK_SIGNS = ("web filter violation", "application control violation", "fortiguard",
                "this site has been blocked", "access to this site is blocked",
                "blocked by your administrator")


def unusable_page(status: int | None, head: str) -> str | None:
    h = (head or "").lower()
    if any(k in h for k in _HOST_FLAG):
        return "host_flagged"
    if any(k in h for k in _BLOCK_SIGNS):
        return "network_filter"
    if any(k in h[:600] for k in _SUSPENDED):
        return "host_suspended"
    if status and status >= 400:
        return f"http_{status}"
    return None


_HAS_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


async def analyze(raw_url: str, deep: bool = True) -> dict:
    t0 = time.perf_counter()
    url = validate(raw_url)
    if not _HAS_SCHEME.match(raw_url.strip()):
        # No scheme typed: browsers try https first, so do the same instead of assuming plain http.
        # A site that really only answers on http keeps http (and is then correctly marked "not HTTPS").
        https_url = "https://" + url[len("http://"):]
        if deep:
            url = https_url if (await safe_fetch(https_url)).ok else url
        else:
            url = https_url
    parts = urlsplit(url)
    host = parts.hostname.lower()
    reg = F.registered_domain(host)
    path = parts.path + ("?" + parts.query if parts.query else "")

    feats = F.extract(url)
    evidence: list[Evidence] = _url_evidence(feats)
    if reg in FREE_HOSTS and host != reg:
        label = host[: -(len(reg) + 1)]
        kit = label.count("-") >= 3 or sum(c.isdigit() for c in label) >= 4
        evidence.append(Evidence("url", "free_hosting", "Hosted on a free website-builder platform",
                                 f"Anyone can publish on {reg} for free. Legitimate people do, but so do many scam campaigns.",
                                 "low", 5))
        if kit:
            evidence.append(Evidence("url", "kit_subdomain", "Auto-generated-looking name on a free platform",
                                     "Several hyphenated or numeric chunks are typical of phishing kits that mass-produce pages.",
                                     "medium", 8))
    layers = {"url": True, "model": MODEL is not None, "page": False, "domain": False, "intel": False,
              "pageai": False}

    # ---- ML model ------------------------------------------------------
    ml = None
    if MODEL:
        ml = MODEL.predict(url)
        if ml["probability"] >= 0.5:
            evidence.append(Evidence("model", "ml_flag", "The AI model rates this URL as phishing-like",
                                     f"Model confidence {ml['probability']*100:.0f}% (trained on {ml['trained_on']}).",
                                     "high" if ml["probability"] >= 0.8 else "medium", 0))
    else:
        evidence.append(Evidence("model", "ml_missing", "No trained model is loaded",
                                 "Run train.py to enable the AI layer; the other layers still work.", "info", 0))

    # ---- brand layer (offline) ---------------------------------------------
    evidence += brand_in_domain(host, path.lower())
    evidence += typosquat_check(host)

    facts = {}
    preview = ""
    intel_status = {}
    fetch_info = {}
    if deep:
        fetch, dom, intel, rend = await asyncio.gather(
            safe_fetch(url), run_domain_intel(host, parts.scheme), threat_intel.run_intel(url),
            browser_analyzer.render(url))
        # threat intel
        iev, intel_status = intel
        evidence += iev
        layers["intel"] = any(v != "not_configured" for v in intel_status.values())
        # domain
        dev, dfacts, davail = dom
        evidence += dev
        facts["domain"] = dfacts
        layers["domain"] = any(davail.values())
        # page
        fetch_info = {"ok": fetch.ok, "error": fetch.error, "status": fetch.status,
                      "final_url": fetch.final_url, "redirects": max(len(fetch.chain) - 1, 0)}
        pev, pfacts = [], {}
        st = rend.chain[-1][1] if (rend.ok and rend.chain) else fetch.status
        head = (rend.title + " " + rend.text[:800]) if rend.ok else (fetch.html or "")[:4000]
        unusable = unusable_page(st, head) if (rend.ok or (fetch.ok and fetch.html)) else None
        if unusable:
            pfacts = {"blocked": unusable, "status": st}
            if unusable == "host_flagged":
                evidence.append(Evidence("page", "host_flagged", "The hosting provider flags this site as malicious",
                                         "The host shows its own malware/phishing warning page instead of the site.",
                                         "high", 35))
            else:
                why = ("a network web filter answered instead of the site" if unusable == "network_filter"
                       else "the hosting provider has suspended or restricted the site" if unusable == "host_suspended"
                       else f"the site answered with an error ({unusable.replace('http_', 'HTTP ')})")
                evidence.append(Evidence("page", "page_unavailable", "The page could not be read",
                                         f"{why}, so the page and behaviour checks did not run. The result relies on the URL, "
                                         "domain and model.", "info", 0))
            facts["browser"] = {"rendered": False, "reason": "page unavailable"}
        if not unusable and fetch.ok and fetch.html:
            pev, pfacts = analyze_page(fetch.final_url, fetch.html, fetch.chain)
            layers["page"] = True
        if rend.ok and not unusable:
            # The rendered page (after JavaScript) is the more complete view: analyse it with the
            # same checks, keep the stronger finding for each check, then add the dynamic findings.
            rev, rfacts = analyze_page(rend.final_url or url, rend.html, rend.chain)
            merged = {e.id: e for e in pev}
            for e in rev:
                if e.id not in merged or e.points > merged[e.id].points:
                    merged[e.id] = e
            pev = list(merged.values())
            pfacts = {**pfacts, **rfacts}
            cloaked = await browser_analyzer.cloaking_check(
                url, fetch.html if fetch.ok else "", rend.password_inputs > 0)
            pev += browser_analyzer.dynamic_evidence(rend, fetch.html if fetch.ok else "", cloaked)
            facts["browser"] = {"rendered": True, "password_fields": rend.password_inputs,
                                "requests": rend.requests, "blocked": rend.blocked,
                                "external_hosts": len(rend.external_hosts), "popups": rend.popups,
                                "dialogs": rend.dialogs, "cloaking": cloaked}
            preview = rend.screenshot_b64
            layers["page"] = True
        elif browser_analyzer.enabled() and rend.error:
            facts["browser"] = {"rendered": False, "reason": rend.error}
        evidence += pev
        if pfacts:
            facts["page"] = pfacts
        # ---- page-content AI (reads what the page says and how it is built) ---------------------
        ai_html = fetch.html if (fetch.ok and fetch.html) else (rend.html if rend.ok else "")
        if PAGE_MODEL and ai_html and not unusable:
            try:
                pm = PAGE_MODEL.predict(fetch.final_url if fetch.ok else rend.final_url, ai_html)
                layers["pageai"] = True
                pp = pm["probability"]
                facts["page_ai"] = {"probability": round(pp, 4), "terms": pm["terms"]}
                pts = round(max(0.0, (pp - PAGEAI_START) / (1 - PAGEAI_START)) * PAGEAI_MAX)
                if pts:
                    evidence.append(Evidence(
                        "pageai", "page_ai_flag", "The AI reads this page's content as phishing-like",
                        f"Content model confidence {pp*100:.0f}%"
                        + (f"; strongest cues: {', '.join(pm['terms'][:4])}." if pm["terms"] else "."),
                        "high" if pp >= 0.8 else "medium", pts))
            except Exception as e:                      # a model problem must never break a scan
                facts["page_ai"] = {"error": type(e).__name__}
        if rend.ok or (fetch.ok and fetch.html):
            pass                                   # page analysed above
        elif fetch.ok:
            layers["page"] = True
            evidence.append(Evidence("page", "non_html", "Not a web page",
                                     f"The link returned {fetch.content_type or 'non-HTML content'}.", "info", 0))
        else:
            evidence.append(Evidence("page", "fetch_failed", "The page could not be inspected",
                                     f"{fetch.error}. The result below relies on the URL, domain and model only.",
                                     "info", 0))
    else:
        evidence.append(Evidence("page", "deep_off", "Quick scan: live page checks were skipped", "", "info", 0))

    r = risk.correlate(ml["probability"] if ml else None, evidence, reg, layers, host, facts)

    # ---- explanation ----------------------------------------------------
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    evidence_sorted = sorted(evidence, key=lambda e: (order[e.severity], -e.points))
    return {
        "url": url,
        "host": host,
        "registered_domain": reg,
        "verdict": r["verdict"],
        "score": r["score"],
        "confidence": r["confidence"],
        "breakdown": r["breakdown"],
        "coverage": r["coverage"],
        "notes": r["notes"],
        "evidence": [e.to_dict() for e in evidence_sorted],
        "actions": risk.ACTIONS[r["verdict"]],
        "model": ({"name": ml["model"], "probability": round(ml["probability"], 4),
                   "trained_on": ml["trained_on"], "explanation": ml["contributions"],
                   "latency_ms": ml["latency_ms"]} if ml else None),
        "intel_status": intel_status,
        "page_fetch": fetch_info,
        "facts": facts,
        "preview": preview,
        "deep": deep,
        "duration_ms": round((time.perf_counter() - t0) * 1000),
    }
