"""DNS, TLS certificate, domain age (RDAP) and typosquatting checks.

Each network step is independent and failure-tolerant: when a check cannot be
performed the layer reports it as unavailable instead of guessing.
"""
from __future__ import annotations

import asyncio
import re
import socket
import ssl
from datetime import datetime, timezone

import httpx

from . import features as F
from .brands import BRANDS, SUSPICIOUS_KEYWORDS, official_domains
from .evidence import Evidence
from .netguard import allow_private, is_public_ip

_HOMOGLYPH = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})


def _lev(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


# ----------------------------------------------------------------------------
def _brand_candidates(token: str):
    plain = token.replace("-", "")
    glyph = plain.translate(_HOMOGLYPH).replace("rn", "m").replace("vv", "w")
    return {plain, glyph}


def typosquat_check(host: str) -> list[Evidence]:
    """Does a hostname word look like a brand name with a small alteration?

    Registered-domain words are checked on their own; subdomain words are only
    checked when a login-style keyword is also present (otherwise 'apply' vs
    'apple' would be a constant false positive).
    """
    reg = F.registered_domain(host)
    if not reg or reg in official_domains():
        return []
    sub, dom, _ = F.split_host(host)
    login_ctx = any(k in host for k in SUSPICIOUS_KEYWORDS)

    scopes = [(t, "domain") for t in dom.split("-") if t]
    if login_ctx:
        scopes += [(t, "subdomain") for l in sub.split(".") for t in l.split("-") if t]

    for token, scope in scopes:
        for brand, cfg in BRANDS.items():
            for kw in cfg["keywords"]:
                if len(kw) < 4 or (scope == "domain" and len(kw) < 5) or len(token) < 3:
                    continue
                for cand in _brand_candidates(token):
                    if cand == kw:
                        if token != kw:  # only reachable via look-alike swaps
                            return [Evidence("brand", "homoglyph", f"Imitates {brand.title()} using look-alike characters",
                                             f"'{token}' reads as '{kw}' once look-alike digits/letters are swapped.",
                                             "high", 25)]
                        continue
                    allowed = 1 if len(kw) < 8 else 2
                    if _lev(cand, kw) <= allowed and abs(len(cand) - len(kw)) <= allowed:
                        return [Evidence("brand", "typosquat", f"Looks like a misspelling of {brand.title()}",
                                         f"'{token}' is {_lev(cand, kw)} character edit away from '{kw}'.",
                                         "high", 25 if scope == "domain" else 20)]
    return []


_BRAND_TEXT = {
    "subdomain": ("{b}'s name is used as a subdomain of an unrelated website",
                  "The address starts with '{kw}', but the real domain you would be visiting is {reg}.", 35),
    "domain_embedded": ("Domain wraps {b}'s name in extra words",
                        "'{reg}' contains '{kw}' but is not one of {b}'s official domains.", 36),
    "domain_exact": ("Domain uses {b}'s name with a different ending",
                     "'{reg}' is not {b}'s official domain.", 22),
    "path": ("Mentions {b} in the link path on an unrelated site",
             "The path contains '{kw}', but the site is {reg}.", 10),
}


def brand_in_domain(host: str, path: str) -> list[Evidence]:
    hit = F.brand_hit(host, path)
    if not hit:
        return []
    brand, kw, where = hit
    reg = F.registered_domain(host)
    title, detail, pts = _BRAND_TEXT[where]
    return [Evidence("brand", "brand_" + where, title.format(b=brand.title()),
                     detail.format(b=brand.title(), kw=kw, reg=reg),
                     "high" if pts >= 30 else "medium", pts)]


# ----------------------------------------------------------------------------
async def dns_check(host: str) -> tuple[list[Evidence], dict]:
    facts = {}
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(loop.run_in_executor(
            None, lambda: socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)), 5)
    except (socket.gaierror, asyncio.TimeoutError):
        facts["resolves"] = False
        return [Evidence("domain", "dns_nxdomain", "Domain does not resolve",
                         "Either it never existed or it was already taken down.", "info", 0)], facts
    ips = sorted({i[4][0] for i in infos})
    facts["resolves"], facts["ips"] = True, ips[:4]
    ev = []
    if not allow_private() and any(not is_public_ip(ip) for ip in ips):
        ev.append(Evidence("domain", "dns_private", "Resolves to a private/internal address",
                           "Public websites do not normally point at internal network space.", "medium", 10))
    return ev, facts


async def tls_check(host: str, port: int = 443) -> tuple[list[Evidence], dict]:
    """Inspect the certificate. Verification failures are findings, not errors."""
    facts, ev = {}, []

    def _ctx():
        # Use the Mozilla CA bundle shipped with certifi, not the operating system store. On Windows
        # Python reads roots lazily, so valid certificates from roots Windows has not "seen" yet were
        # reported as "not trusted" (found by the end-to-end evaluation: 18% of legitimate sites).
        try:
            import certifi
            return ssl.create_default_context(cafile=certifi.where())
        except Exception:
            return ssl.create_default_context()

    def work():
        ctx = _ctx()
        try:
            with socket.create_connection((host, port), timeout=5) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    return {"verified": True, "cert": s.getpeercert()}
        except ssl.SSLCertVerificationError as e:
            reason = getattr(e, "verify_message", str(e))
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            try:
                with socket.create_connection((host, port), timeout=5) as raw:
                    with ctx2.wrap_socket(raw, server_hostname=host) as s:
                        der = s.getpeercert(binary_form=True)
                return {"verified": False, "reason": reason, "der": bool(der)}
            except Exception:
                return {"verified": False, "reason": reason}
        except Exception as e:  # no TLS on 443, timeout, etc.
            return {"unavailable": type(e).__name__}

    loop = asyncio.get_running_loop()
    try:
        r = await asyncio.wait_for(loop.run_in_executor(None, work), 10)
    except asyncio.TimeoutError:
        return [], {"tls": "timeout"}

    if "unavailable" in r:
        facts["tls"] = "unavailable"
        return [], facts

    if not r["verified"]:
        reason = r.get("reason", "certificate failed validation")
        facts["tls"] = f"invalid: {reason}"
        rl = reason.lower()
        if "local issuer" in rl:
            # The chain could not be completed: a missing intermediate on the server, or a network that
            # inspects HTTPS with its own certificate. Weak evidence, unlike self-signed/expired/wrong name.
            facts["tls"] = f"invalid: {reason}"
            ev.append(Evidence("domain", "tls_chain", "Certificate chain could not be verified",
                               f"{reason}. Often a server or network configuration issue rather than an attack.",
                               "low", 3))
            return ev, facts
        sev, pts = ("high", 15) if "self" in rl or "expired" in rl or "match" in rl else ("medium", 10)
        ev.append(Evidence("domain", "tls_invalid", "HTTPS certificate is not trusted",
                           f"Browsers would warn about this site: {reason}.", sev, pts))
        return ev, facts

    cert = r["cert"]
    facts["tls"] = "valid"
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    facts["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
    try:
        nb = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - nb).days
        facts["cert_age_days"] = age
        if age < 7:
            ev.append(Evidence("domain", "tls_new", "HTTPS certificate was issued in the last week",
                               "Valid certificates are free, so this is weak on its own, but scam sites are usually brand new.",
                               "low", 5))
    except Exception:
        pass
    return ev, facts


_AGE_CACHE: dict[str, tuple[float, int]] = {}      # registered domain -> (fetched at, age in days)
_AGE_TTL = 24 * 3600


def _age_evidence(days: int) -> tuple[list[Evidence], dict]:
    facts = {"domain_age_days": days}
    if days < 30:
        return [Evidence("domain", "domain_new", f"Domain registered only {days} days ago",
                         "Most phishing domains are used within weeks of being registered.", "high", 20)], facts
    if days < 180:
        return [Evidence("domain", "domain_young", f"Domain is only {days} days old",
                         "Young domains deserve extra caution.", "low", 8)], facts
    return [Evidence("domain", "domain_established", f"Domain has existed for {days // 365 if days >= 365 else days // 30} "
                     f"{'year(s)' if days >= 365 else 'month(s)'}", "", "info", 0)], facts


async def domain_age(reg_domain: str) -> tuple[list[Evidence], dict]:
    """Domain registration age via RDAP (the HTTP successor to WHOIS).

    The public rdap.org redirector is sometimes slow or rate-limited, so successful answers are
    cached for a day and a failed lookup is retried once. If it still fails the age is reported as
    unavailable (never guessed)."""
    import time
    hit = _AGE_CACHE.get(reg_domain)
    if hit and time.time() - hit[0] < _AGE_TTL:
        return _age_evidence(hit[1])
    last = {"rdap": "unavailable"}
    for attempt in range(2):
        try:
            async with httpx.AsyncClient(timeout=8, follow_redirects=True,
                                         headers={"User-Agent": "PhishGuardAnalyzer/1.0"}) as c:
                r = await c.get(f"https://rdap.org/domain/{reg_domain}")
            if r.status_code != 200:
                last = {"rdap": f"status {r.status_code}"}
                if r.status_code in (404, 400):          # the registry has no record: retrying won't help
                    break
                continue
            events = r.json().get("events", [])
            reg = next((e["eventDate"] for e in events if e.get("eventAction") == "registration"), None)
            if not reg:
                return [], {"rdap": "no registration date"}
            d = datetime.fromisoformat(reg.replace("Z", "+00:00"))
            days = (datetime.now(timezone.utc) - d).days
            _AGE_CACHE[reg_domain] = (time.time(), days)
            return _age_evidence(days)
        except Exception as e:
            last = {"rdap": type(e).__name__}
    return [], last


async def run_domain_intel(host: str, scheme: str) -> tuple[list[Evidence], dict, dict]:
    """Run DNS, TLS and RDAP in parallel. Returns (evidence, facts, availability)."""
    reg = F.registered_domain(host)
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))
    ev, facts, avail = [], {}, {}

    dns_ev, dns_f = await dns_check(host)
    ev += dns_ev
    facts.update(dns_f)
    avail["dns"] = True
    if not dns_f.get("resolves"):
        avail["tls"] = avail["rdap"] = False
        return ev, facts, avail

    tasks = [tls_check(host)]
    if not is_ip:
        tasks.append(domain_age(reg))
    res = await asyncio.gather(*tasks)
    tev, tf = res[0]
    ev += tev
    facts.update(tf)
    avail["tls"] = tf.get("tls") not in (None, "unavailable", "timeout")
    if len(res) > 1:
        aev, af = res[1]
        ev += aev
        facts.update(af)
        avail["rdap"] = "domain_age_days" in af
    else:
        avail["rdap"] = False
    return ev, facts, avail
