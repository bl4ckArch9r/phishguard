"""Dynamic behaviour analysis: load the page in an isolated headless Chromium and watch
what it actually does once its JavaScript has run.

Static HTML analysis (page_analyzer.py) cannot see a login form that is built by
JavaScript, a page that serves a different document to scanners than to browsers, or
a page that opens pop-ups, shows dialogs, starts a download or submits a form by
itself. This module catches those.

Safety design (the page is hostile, so the browser is boxed in):
  * The browser has NO network of its own. DNS is disabled and a dead proxy is set, and
    every request it makes is intercepted and answered by netguard.fetch_hop, which
    applies the same SSRF rules as the static fetch (public IPs only, pinned address,
    size caps, one redirect hop at a time).
  * Only GET requests are answered. Any POST (e.g. an auto-submitted form) is blocked and
    reported, never sent. Downloads are refused, pop-ups are closed, dialogs dismissed.
  * Fresh context per scan: no cookies, storage or permissions. Time and request budgets.
  * Page-supplied text is returned as data and only ever shown with textContent in the UI.

Optional: needs `pip install playwright` and `playwright install chromium`. Without them
PhishGuard simply keeps using the static analysis. Disable with PHISHGUARD_BROWSER=0.
Run the server with plain `uvicorn ... ` (no --reload) on Windows so subprocesses work.
"""
from __future__ import annotations

import asyncio
import base64
import os
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

from . import netguard
from .evidence import Evidence

NAV_TIMEOUT_MS = 10_000
SETTLE_MS = 900
MAX_REQUESTS = 60
MAX_TOTAL_BYTES = 8_000_000
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
ALLOWED_TYPES = {"document", "script", "stylesheet", "image", "xhr", "fetch"}
DROP_HEADERS = {"content-encoding", "content-length", "transfer-encoding", "set-cookie", "connection"}
REDIRECTS = (301, 302, 303, 307, 308)
PASS_HEADERS = ("accept", "accept-language", "referer")

_PW_RE = re.compile(r"""type\s*=\s*["']?password""", re.I)

_state = {"pw": None, "browser": None, "loop": None}
_lock = asyncio.Lock()
_sem = asyncio.Semaphore(2)


def enabled() -> bool:
    if os.environ.get("PHISHGUARD_BROWSER", "auto") == "0":
        return False
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


@dataclass
class Render:
    ok: bool = False
    error: str | None = None
    final_url: str = ""
    chain: list = field(default_factory=list)        # [(url, status)] for the main document
    html: str = ""                                   # DOM after JavaScript ran
    title: str = ""
    text: str = ""
    password_inputs: int = 0
    visible_password_inputs: int = 0
    forms: list = field(default_factory=list)
    popups: int = 0
    dialogs: int = 0
    downloads: int = 0
    post_attempts: int = 0
    requests: int = 0
    blocked: int = 0
    external_hosts: list = field(default_factory=list)
    screenshot_b64: str = ""


async def _follow(client, url, headers, chain=None, hops=5):
    """GET url through the pinned fetcher, following redirects one validated hop at a time
    (the browser is never handed a 3xx, which it would not follow). Returns the last response."""
    cur = url
    for _ in range(hops + 1):
        status, hdrs, body, trunc = await netguard.fetch_hop(client, cur, headers)
        loc = next((v for k, v in hdrs.items() if k.lower() == "location"), None)
        if status in REDIRECTS and loc:
            if chain is not None:
                chain.append((cur, status))
            cur = urljoin(cur, loc)
            continue
        if chain is not None:
            chain.append((cur, status))
        return cur, status, hdrs, body
    raise netguard.Blocked("too many redirects")


async def _get_browser():
    async with _lock:
        loop = asyncio.get_running_loop()
        b = _state["browser"]
        if b is not None and _state["loop"] is loop and b.is_connected():
            return b
        if _state["loop"] is not loop:           # a different event loop (tests): start fresh
            _state.update(pw=None, browser=None)
        _state["loop"] = loop
        from playwright.async_api import async_playwright
        if _state["pw"] is None:
            _state["pw"] = await async_playwright().start()
        args = ["--host-resolver-rules=MAP * ~NOTFOUND", "--proxy-server=http://127.0.0.1:9",
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                "--disable-dev-shm-usage", "--mute-audio", "--no-first-run"]
        if hasattr(os, "geteuid") and os.geteuid() == 0 or os.environ.get("PHISHGUARD_BROWSER_NOSANDBOX") == "1":
            args.append("--no-sandbox")          # containers run as root; the box is the container
        _state["browser"] = await _state["pw"].chromium.launch(headless=True, args=args)
        return _state["browser"]


async def close():
    async with _lock:
        if _state["browser"] is not None:
            try:
                await _state["browser"].close()
            except Exception:
                pass
            _state["browser"] = None
        if _state["pw"] is not None:
            try:
                await _state["pw"].stop()
            except Exception:
                pass
            _state["pw"] = None


_EXTRACT = """() => {
  const vis = (el) => { const s = getComputedStyle(el); const r = el.getBoundingClientRect();
    return s.display !== 'none' && s.visibility !== 'hidden' && r.width > 1 && r.height > 1; };
  const pw = [...document.querySelectorAll('input[type=password]')];
  const forms = [...document.forms].slice(0, 10).map(f => ({
    action: f.getAttribute('action') || '', method: (f.method || 'get').toLowerCase(),
    password: !!f.querySelector('input[type=password]')}));
  return { title: document.title || '', text: (document.body ? document.body.innerText : '').slice(0, 4000),
           pw: pw.length, pwVisible: pw.filter(vis).length, forms };
}"""


async def render(url: str) -> Render:
    r = Render()
    if not enabled():
        r.error = "rendered-page analysis is not installed"
        return r
    try:
        browser = await _get_browser()
    except Exception as e:                                   # missing browser binary, crash, ...
        r.error = f"browser unavailable ({type(e).__name__})"
        return r

    async with _sem:
        ctx = None
        try:
            ctx = await browser.new_context(
                user_agent=BROWSER_UA, viewport={"width": 1280, "height": 800}, locale="en-US",
                accept_downloads=False, service_workers="block", ignore_https_errors=True)
            page = await ctx.new_page()
            budget = {"bytes": 0}
            hosts: set[str] = set()
            prefetched: dict = {}
            origin = (urlsplit(url).hostname or "").lower()

            async with httpx.AsyncClient(verify=False, timeout=netguard.TIMEOUT, follow_redirects=False) as client:

                async def handler(route):
                    req = route.request
                    r.requests += 1
                    try:
                        if req.method != "GET":
                            r.blocked += 1
                            if req.resource_type == "document":
                                r.post_attempts += 1
                                # 204 = "stay on this page": the submission goes nowhere and the page stays intact
                                return await route.fulfill(status=204, body=b"")
                            return await route.abort()
                        if (req.resource_type not in ALLOWED_TYPES or r.requests > MAX_REQUESTS
                                or budget["bytes"] > MAX_TOTAL_BYTES):
                            r.blocked += 1
                            return await route.abort()
                        h = {"User-Agent": BROWSER_UA}
                        for k in PASS_HEADERS:
                            if req.headers.get(k):
                                h[k] = req.headers[k]
                        if req.url in prefetched:
                            status, headers, body = prefetched.pop(req.url)
                        else:
                            fchain = [] if (req.resource_type == "document" and req.frame == page.main_frame) else None
                            _, status, headers, body = await _follow(client, req.url, h, chain=fchain)
                            if fchain:
                                r.chain.extend(fchain)
                        budget["bytes"] += len(body)
                        host = (urlsplit(req.url).hostname or "").lower()
                        if host and host != origin:
                            hosts.add(host)
                        headers = {k: v for k, v in headers.items() if k.lower() not in DROP_HEADERS}
                        await route.fulfill(status=status, headers=headers, body=body)
                    except Exception:                       # blocked, DNS failure, timeout, closed page ...
                        r.blocked += 1
                        try:
                            await route.abort()
                        except Exception:
                            pass

                await page.route("**/*", handler)
                page.on("popup", lambda p: (setattr(r, "popups", r.popups + 1), asyncio.ensure_future(p.close())))

                def on_dialog(d):
                    r.dialogs += 1
                    asyncio.ensure_future(d.dismiss())
                page.on("dialog", on_dialog)
                page.on("download", lambda d: setattr(r, "downloads", r.downloads + 1))

                # Resolve the redirect chain ourselves, validating every hop, then load the final address.
                try:
                    start_headers = {"User-Agent": BROWSER_UA, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
                    final, st, hd, bd = await _follow(client, url, start_headers, chain=r.chain)
                    prefetched[final] = (st, hd, bd)
                except (netguard.Blocked, LookupError) as e:
                    r.error = f"blocked or unreachable: {e}"
                    return r
                except httpx.HTTPError as e:
                    r.error = f"unreachable ({type(e).__name__})"
                    return r
                try:
                    await page.goto(final, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
                except Exception as e:
                    # A page that submits a form by itself makes goto() report an aborted navigation
                    # (we answered the POST with "stay here"); the page itself did load, so carry on.
                    interrupted = r.post_attempts > 0 and page.url.startswith(("http://", "https://"))
                    if not interrupted:
                        r.error = "page did not load" if "ERR_" in str(e) or "Timeout" in str(e) else type(e).__name__
                        return r
                try:
                    await page.wait_for_load_state("networkidle", timeout=3000)
                except Exception:
                    pass
                await page.wait_for_timeout(SETTLE_MS)

                if page.url.startswith(("chrome-error:", "about:neterror")):
                    r.error = "page did not load in the browser"
                    return r
                info = await page.evaluate(_EXTRACT)
                r.final_url = page.url
                r.html = (await page.content())[:1_500_000]
                r.title = str(info.get("title", ""))[:200]
                r.text = str(info.get("text", ""))
                r.password_inputs = int(info.get("pw", 0))
                r.visible_password_inputs = int(info.get("pwVisible", 0))
                r.forms = info.get("forms", [])
                r.external_hosts = sorted(hosts)[:30]
                try:
                    shot = await page.screenshot(type="jpeg", quality=45, timeout=4000)
                    r.screenshot_b64 = base64.b64encode(shot).decode("ascii")
                except Exception:
                    pass
                r.ok = True
        except Exception as e:
            r.error = r.error or type(e).__name__
        finally:
            if ctx is not None:
                try:
                    await ctx.close()
                except Exception:
                    pass
    return r


async def cloaking_check(url: str, scanner_html: str, rendered_has_password: bool) -> bool:
    """True if a normal-browser User-Agent gets a login form that the scanner User-Agent did not."""
    if not rendered_has_password or _PW_RE.search(scanner_html or ""):
        return False
    res = await netguard.safe_fetch(url, ua=BROWSER_UA)
    return bool(res.ok and _PW_RE.search(res.html or ""))


def dynamic_evidence(r: Render, static_html: str, cloaked: bool) -> list[Evidence]:
    ev: list[Evidence] = []
    if not r.ok:
        return ev
    static_pw = bool(_PW_RE.search(static_html or ""))
    if cloaked:
        ev.append(Evidence("page", "cloaking", "Shows a login form to browsers but not to scanners",
                           "The same address returns a different page depending on who asks, a common way for "
                           "phishing kits to hide from security tools.", "critical", 25))
    elif r.password_inputs and not static_pw:
        ev.append(Evidence("page", "js_built_login", "Login form is created by JavaScript",
                           "The password field only exists after scripts run, so it is invisible to simple page scanners.",
                           "low", 4))
    if r.post_attempts:
        ev.append(Evidence("page", "auto_submit", "Page tried to submit a form by itself",
                           "A form was sent without any click. The submission was blocked.", "high", 15))
    if r.popups:
        ev.append(Evidence("page", "popup_on_load", "Opens pop-up windows on load",
                           f"{r.popups} window(s) tried to open without any click. They were closed.", "medium", 8))
    if r.dialogs:
        ev.append(Evidence("page", "dialog_on_load", "Shows alert or prompt dialogs on load",
                           "Scam pages use dialogs to pressure or trick visitors. They were dismissed.", "medium", 8))
    if r.downloads:
        ev.append(Evidence("page", "download_attempt", "Tried to download a file automatically",
                           "The download was refused.", "high", 15))
    return ev
