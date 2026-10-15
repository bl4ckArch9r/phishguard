"""SSRF-safe networking helpers.

PhishGuard fetches user-supplied URLs, which is exactly the situation OWASP
describes as SSRF. Defences implemented here:
  1. Only http/https; no credentials in the URL.
  2. The hostname is resolved once and every returned address must be public.
  3. The request is then sent to that pinned IP (Host header + SNI set to the
     real name), which closes the DNS-rebinding window between check and use.
  4. Redirects are followed manually and each hop is re-validated.
  5. Response size and time are capped; only text/html is parsed.

Set PHISHGUARD_ALLOW_PRIVATE=1 ONLY for local tests against 127.0.0.1.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

MAX_BYTES = 1_500_000
MAX_REDIRECTS = 5
MAX_SUB_BYTES = 2_000_000   # per sub-resource when feeding the headless browser
TIMEOUT = 8.0
UA = "PhishGuardAnalyzer/1.0 (security analysis; passive GET only)"


def allow_private() -> bool:
    return os.environ.get("PHISHGUARD_ALLOW_PRIVATE") == "1"


class Blocked(Exception):
    pass


def is_public_ip(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
                or a.is_reserved or a.is_unspecified)


async def resolve_public(host: str, port: int) -> list[str]:
    """Resolve host and return addresses; raise Blocked if any is non-public."""
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.run_in_executor(
            None, lambda: socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
    except socket.gaierror as e:
        raise LookupError(f"DNS lookup failed: {e}") from e
    addrs = []
    for info in infos:
        ip = info[4][0]
        if ip not in addrs:
            addrs.append(ip)
    if not addrs:
        raise LookupError("no addresses")
    if not allow_private():
        bad = [a for a in addrs if not is_public_ip(a)]
        if bad:
            raise Blocked(f"resolves to a non-public address ({bad[0]})")
    return addrs


@dataclass
class FetchResult:
    ok: bool = False
    error: str | None = None
    final_url: str = ""
    status: int | None = None
    chain: list = field(default_factory=list)       # [(url, status)]
    html: str = ""
    content_type: str = ""
    truncated: bool = False
    ip: str | None = None


async def safe_fetch(url: str, ua: str | None = None) -> FetchResult:
    res = FetchResult()
    current = url
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT, follow_redirects=False,
                                 headers={"User-Agent": ua or UA, "Accept": "text/html,*/*;q=0.5"}) as client:
        for _ in range(MAX_REDIRECTS + 1):
            parts = urlsplit(current)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                res.error = "unsupported URL"
                return res
            if parts.username or parts.password:
                res.error = "credentials in URL are not fetched"
                return res
            port = parts.port or (443 if parts.scheme == "https" else 80)
            try:
                addrs = await resolve_public(parts.hostname, port)
            except Blocked as e:
                res.error = f"blocked: {e}"
                return res
            except LookupError as e:
                res.error = str(e)
                return res
            ip = addrs[0]
            res.ip = ip
            ip_lit = f"[{ip}]" if ":" in ip else ip
            netloc = f"{ip_lit}:{port}" if parts.port else ip_lit
            pinned = parts._replace(netloc=netloc).geturl()
            try:
                async with client.stream(
                        "GET", pinned,
                        headers={"Host": parts.netloc.split("@")[-1]},
                        extensions={"sni_hostname": parts.hostname}) as r:
                    res.status = r.status_code
                    res.chain.append((current, r.status_code))
                    if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("location"):
                        current = urljoin(current, r.headers["location"])
                        continue
                    res.final_url = current
                    res.content_type = r.headers.get("content-type", "")
                    buf = bytearray()
                    async for chunk in r.aiter_bytes():
                        buf.extend(chunk)
                        if len(buf) > MAX_BYTES:
                            res.truncated = True
                            break
                    if "html" in res.content_type.lower() or not res.content_type:
                        res.html = bytes(buf).decode(r.encoding or "utf-8", errors="replace")
                    res.ok = True
                    return res
            except httpx.TimeoutException:
                res.error = "timed out"
                return res
            except httpx.HTTPError as e:
                res.error = f"{type(e).__name__}"
                return res
        res.error = "too many redirects"
        res.final_url = current
        return res


async def fetch_hop(client: httpx.AsyncClient, url: str, headers: dict | None = None,
                    max_bytes: int = MAX_SUB_BYTES):
    """ONE validated, IP-pinned GET with no redirect following.

    The headless browser never touches the network itself: every request it makes is
    passed through here and the answer is handed back to it, so it gets the same
    SSRF protections as safe_fetch (public addresses only, pinned IP, size cap).
    Returns (status, headers, body, truncated). Raises Blocked / LookupError / httpx.HTTPError."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise Blocked("unsupported URL")
    if parts.username or parts.password:
        raise Blocked("credentials in URL are not fetched")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    addrs = await resolve_public(parts.hostname, port)
    ip = addrs[0]
    ip_lit = f"[{ip}]" if ":" in ip else ip
    netloc = f"{ip_lit}:{port}" if parts.port else ip_lit
    pinned = parts._replace(netloc=netloc).geturl()
    hdrs = dict(headers or {})
    hdrs["Host"] = parts.netloc.split("@")[-1]
    async with client.stream("GET", pinned, headers=hdrs,
                             extensions={"sni_hostname": parts.hostname}) as r:
        buf = bytearray()
        truncated = False
        async for chunk in r.aiter_bytes():
            buf.extend(chunk)
            if len(buf) > max_bytes:
                truncated = True
                break
        return r.status_code, dict(r.headers), bytes(buf), truncated
