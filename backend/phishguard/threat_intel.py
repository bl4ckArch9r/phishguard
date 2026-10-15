"""Threat-intelligence lookups.

Providers (each is optional and reported as configured / not configured):
  * local feed   - data/blocklist.txt, one URL or domain per line (e.g. the
                   OpenPhish community feed). Refresh with:  python -m phishguard.threat_intel refresh
  * VirusTotal   - env VIRUSTOTAL_API_KEY       (read-only lookup, never submits the URL)
  * Safe Browsing- env GOOGLE_SAFE_BROWSING_KEY
  * URLhaus      - env URLHAUS_AUTH_KEY         (abuse.ch now requires a free Auth-Key)

IMPORTANT: a provider that is not configured contributes NOTHING. The report
shows it as "not configured" so a missing feed is never mistaken for a clean
result.
"""
from __future__ import annotations

import asyncio
import base64
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from . import features as F
from .evidence import Evidence

DATA = Path(__file__).resolve().parent.parent / "data"
BLOCKLIST = DATA / "blocklist.txt"
FEED_URL = "https://openphish.com/feed.txt"

_cache = {"mtime": None, "urls": set(), "hosts": set()}


def _load_blocklist():
    if not BLOCKLIST.exists():
        _cache.update(mtime=None, urls=set(), hosts=set())
        return
    m = BLOCKLIST.stat().st_mtime
    if _cache["mtime"] == m:
        return
    urls, hosts = set(), set()
    for line in BLOCKLIST.read_text(errors="ignore").splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        urls.add(line.rstrip("/"))
        h = urlsplit(line if "://" in line else "http://" + line).hostname
        if h:
            hosts.add(h)
    _cache.update(mtime=m, urls=urls, hosts=hosts)


def feed_size() -> int:
    _load_blocklist()
    return len(_cache["urls"])


def local_feed_lookup(url: str) -> Evidence | None:
    _load_blocklist()
    u = F.normalize_url(url).lower().rstrip("/")
    host = urlsplit(u).hostname or ""
    if u in _cache["urls"] or (u.split("://", 1)[-1]) in _cache["urls"]:
        return Evidence("intel", "feed_url_match", "Listed in the phishing blocklist",
                        "This exact URL appears in the local phishing feed.", "critical", 60)
    if host and host in _cache["hosts"]:
        return Evidence("intel", "feed_host_match", "Host appears in the phishing blocklist",
                        f"Another URL on {host} is listed in the local phishing feed.", "high", 40)
    return None


# --------------------------------------------------------------------------
async def virustotal(url: str, client: httpx.AsyncClient) -> Evidence | None | str:
    key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not key:
        return "not_configured"
    uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    r = await client.get(f"https://www.virustotal.com/api/v3/urls/{uid}", headers={"x-apikey": key})
    if r.status_code == 404:
        return None
    r.raise_for_status()
    stats = r.json()["data"]["attributes"].get("last_analysis_stats", {})
    mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
    if mal >= 3:
        return Evidence("intel", "vt_malicious", f"{mal} security vendors flag this URL as malicious",
                        "From VirusTotal's existing analysis results.", "critical", 55)
    if mal >= 1 or sus >= 2:
        return Evidence("intel", "vt_suspicious", f"{mal + sus} security vendor(s) flag this URL",
                        "From VirusTotal's existing analysis results.", "medium", 20)
    return None


async def safe_browsing(url: str, client: httpx.AsyncClient) -> Evidence | None | str:
    key = os.environ.get("GOOGLE_SAFE_BROWSING_KEY")
    if not key:
        return "not_configured"
    body = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["SOCIAL_ENGINEERING", "MALWARE", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    r = await client.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}", json=body)
    r.raise_for_status()
    matches = r.json().get("matches")
    if matches:
        kind = matches[0].get("threatType", "threat").replace("_", " ").lower()
        return Evidence("intel", "gsb_match", "Google Safe Browsing lists this URL",
                        f"Threat type: {kind}.", "critical", 60)
    return None


async def urlhaus(url: str, client: httpx.AsyncClient) -> Evidence | None | str:
    key = os.environ.get("URLHAUS_AUTH_KEY")
    if not key:
        return "not_configured"
    r = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, headers={"Auth-Key": key})
    r.raise_for_status()
    j = r.json()
    if j.get("query_status") == "ok":
        return Evidence("intel", "urlhaus_match", "Listed in URLhaus (abuse.ch)",
                        f"Status: {j.get('url_status', 'unknown')}.", "critical", 55)
    return None


PROVIDERS = {"virustotal": virustotal, "safe_browsing": safe_browsing, "urlhaus": urlhaus}


async def run_intel(url: str) -> tuple[list[Evidence], dict]:
    """Returns (evidence, provider_status). Status values: clean | listed | not_configured | error."""
    url = F.normalize_url(url)
    ev, status = [], {}

    hit = local_feed_lookup(url)
    status["local_feed"] = ("listed" if hit else "clean") if feed_size() else "not_configured"
    if hit:
        ev.append(hit)

    async with httpx.AsyncClient(timeout=6) as client:
        async def one(name, fn):
            try:
                return name, await fn(url, client)
            except Exception as e:
                return name, f"error:{type(e).__name__}"

        for name, res in await asyncio.gather(*(one(n, f) for n, f in PROVIDERS.items())):
            if res == "not_configured":
                status[name] = "not_configured"
            elif isinstance(res, str):
                status[name] = "error"
            elif res is None:
                status[name] = "clean"
            else:
                status[name] = "listed"
                ev.append(res)
    return ev, status


def refresh_feed() -> int:
    """Download the OpenPhish community feed into data/blocklist.txt."""
    DATA.mkdir(exist_ok=True)
    r = httpx.get(FEED_URL, timeout=30, follow_redirects=True)
    r.raise_for_status()
    BLOCKLIST.write_text(r.text)
    return len([l for l in r.text.splitlines() if l.strip()])


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "refresh":
        print(f"feed refreshed: {refresh_feed()} entries")
    else:
        print("usage: python -m phishguard.threat_intel refresh")
