"""Lexical URL features. Pure string analysis: no network access.

The same function is used at training time and at inference time, so the model
never sees a feature at runtime that it was not trained on.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlsplit

import tldextract

from .brands import (BRANDS, SHORTENERS, SUSPICIOUS_KEYWORDS, SUSPICIOUS_TLDS,
                     official_domains)

_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_OFFICIAL = official_domains()

FEATURE_NAMES = [
    "url_len", "host_len", "path_len", "query_len",
    "dots_in_host", "hyphens_in_host", "digits_in_host", "digit_ratio_url",
    "subdomain_count", "has_ip_host", "has_at", "nonstandard_port", "is_https",
    "special_chars", "double_slash_in_path", "is_shortener", "suspicious_tld",
    "host_entropy", "longest_label", "path_segments", "has_punycode",
    "keyword_hits_host", "keyword_hits_path", "brand_mismatch", "pct_encoded",
    "tld_len", "digit_in_alpha_label", "consonant_run", "random_label",
]

# Plain-language description used by the explanation layer.
FEATURE_TEXT = {
    "url_len": "The URL is unusually long",
    "host_len": "The hostname is unusually long",
    "path_len": "The path after the domain is unusually long",
    "query_len": "The query string is unusually long",
    "dots_in_host": "The hostname has many dots (deep subdomain nesting)",
    "hyphens_in_host": "The hostname contains several hyphens",
    "digits_in_host": "The hostname contains many digits",
    "digit_ratio_url": "A large share of the URL is digits",
    "subdomain_count": "Many subdomains sit in front of the real domain",
    "has_ip_host": "The address is a raw IP instead of a domain name",
    "has_at": "The URL contains an '@' that can hide the real destination",
    "nonstandard_port": "The URL uses an unusual port",
    "is_https": "The link does not use HTTPS",
    "special_chars": "The URL contains many special characters",
    "double_slash_in_path": "The path contains a '//' redirect-style pattern",
    "is_shortener": "The link goes through a URL shortener, hiding its destination",
    "suspicious_tld": "The domain ends in a top-level domain often abused for scams",
    "host_entropy": "The hostname has an unusually unpredictable mix of letters",
    "longest_label": "The hostname has a very long label",
    "path_segments": "The path has many segments",
    "has_punycode": "The hostname uses punycode (can imitate other characters)",
    "keyword_hits_host": "The hostname contains words like login/secure/verify",
    "keyword_hits_path": "The path contains words like login/verify/account",
    "brand_mismatch": "A well-known brand name appears but the domain is not the brand's",
    "pct_encoded": "The URL contains percent-encoded characters",
    "tld_len": "The domain ending is unusually long",
    "digit_in_alpha_label": "Digits are mixed into a word-like domain label",
    "consonant_run": "Part of the hostname is a long run of consonants (not a real word)",
    "random_label": "A hostname part looks randomly generated",
}


_CONS = re.compile(r"[bcdfghjklmnpqrstvwxz]+")


def _consonant_run(labels) -> int:
    return max((len(m) for l in labels for m in _CONS.findall(l)), default=0)


def _random_label(labels) -> int:
    """True when a hostname word looks machine-generated rather than like a word.
    Checked per hyphen-separated token: a long consonant run, or almost no vowels."""
    for l in labels:
        for tok in l.split("-"):
            if len(tok) < 9 or not tok.isalnum():
                continue
            vowels = sum(ch in "aeiou" for ch in tok) / len(tok)
            if _consonant_run([tok]) >= 7 or vowels < 0.2:
                return 1
    return 0


def normalize_url(raw: str) -> str:
    u = (raw or "").strip()
    if not u:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", u):
        u = "http://" + u
    return u


def model_text(raw: str) -> str:
    """Text the character n-gram model reads: no scheme, no leading 'www.'.

    Many public datasets store URLs without a scheme while people paste them with
    one; removing it (and 'www.') in training AND inference stops the model from
    learning that quirk of the data collection instead of the address itself."""
    u = normalize_url(raw)
    u = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", u)
    return re.sub(r"^www\d*\.", "", u, flags=re.I)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def registered_domain(host: str) -> str:
    ext = _extract(host)
    if ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return host.lower()


def split_host(host: str):
    ext = _extract(host)
    return ext.subdomain.lower(), ext.domain.lower(), ext.suffix.lower()


_BRAND_SUFFIX_WORDS = set(SUSPICIOUS_KEYWORDS) | {"online", "pay", "service", "official", "help", "mail", "web", "app"}
_PRIORITY = {"subdomain": 0, "domain_embedded": 1, "domain_exact": 2, "path": 3}


def _token_match(label: str, kw: str) -> bool:
    """kw is a hyphen-delimited token of label, or label = kw + known suspicious word."""
    for tok in label.split("-"):
        if tok == kw:
            return True
        if tok.startswith(kw) and tok[len(kw):] in _BRAND_SUFFIX_WORDS:
            return True
        if tok.endswith(kw) and tok[: -len(kw)] in _BRAND_SUFFIX_WORDS:
            return True
    return False


def brand_hit(host: str, path: str = ""):
    """Return (brand, keyword, where) for the strongest place a brand name is
    used by a domain that does not belong to that brand, else None.
    where: subdomain | domain_embedded | domain_exact | path"""
    reg = registered_domain(host)
    if reg in _OFFICIAL:
        return None
    sub, dom, _ = split_host(host)
    best = None
    for brand, cfg in BRANDS.items():
        if reg in cfg["official"]:
            continue
        for kw in cfg["keywords"]:
            where = None
            if any(_token_match(l, kw) for l in sub.split(".") if l):
                where = "subdomain"
            elif dom == kw:
                where = "domain_exact"
            elif _token_match(dom, kw):
                where = "domain_embedded"
            elif len(kw) >= 5 and kw in path.lower():
                where = "path"
            if where and (best is None or _PRIORITY[where] < _PRIORITY[best[2]]):
                best = (brand, kw, where)
    return best


def extract(url: str) -> dict:
    url = normalize_url(url)
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        parts = urlsplit("http://invalid")
        host, port = "", None
    path, query = parts.path or "", parts.query or ""

    is_ip = bool(_IPV4.match(host))
    sub, dom, suffix = ("", host, "") if is_ip else split_host(host)
    labels = [l for l in host.split(".") if l]
    sub_labels = [l for l in sub.split(".") if l]
    rest = (path + "?" + query).lower() if query else path.lower()

    kw_host = sum(1 for k in SUSPICIOUS_KEYWORDS if k in host)
    kw_path = sum(1 for k in SUSPICIOUS_KEYWORDS if k in rest)
    reg = registered_domain(host) if host else ""

    f = {
        "url_len": len(url),
        "host_len": len(host),
        "path_len": len(path),
        "query_len": len(query),
        "dots_in_host": host.count("."),
        "hyphens_in_host": host.count("-"),
        "digits_in_host": sum(ch.isdigit() for ch in host),
        "digit_ratio_url": sum(ch.isdigit() for ch in url) / max(len(url), 1),
        "subdomain_count": len(sub_labels),
        "has_ip_host": int(is_ip),
        "has_at": int("@" in url),
        "nonstandard_port": int(port not in (None, 80, 443)),
        "is_https": int(parts.scheme == "https"),
        "special_chars": sum(url.count(c) for c in "?&=%_~#$!*"),
        "double_slash_in_path": int("//" in path),
        "is_shortener": int(reg in SHORTENERS),
        "suspicious_tld": int(suffix.split(".")[-1] in SUSPICIOUS_TLDS) if suffix else 0,
        "host_entropy": max((_entropy(l) for l in labels if len(l) >= 6), default=0.0),
        "longest_label": max((len(l) for l in labels), default=0),
        "path_segments": len([s for s in path.split("/") if s]),
        "has_punycode": int("xn--" in host),
        "keyword_hits_host": kw_host,
        "keyword_hits_path": kw_path,
        "brand_mismatch": int(brand_hit(host, rest) is not None) if host else 0,
        "pct_encoded": len(re.findall(r"%[0-9a-fA-F]{2}", url)),
        "tld_len": len(suffix.split(".")[-1]) if suffix else 0,
        "digit_in_alpha_label": int(bool(re.search(r"[a-z]\d|\d[a-z]", dom)) and not is_ip),
        "consonant_run": 0 if is_ip else _consonant_run(labels),
        "random_label": 0 if is_ip else _random_label(labels),
    }
    return f
