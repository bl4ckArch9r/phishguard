import pytest
from fastapi.testclient import TestClient

from phishguard import main


@pytest.fixture(scope="module")
def client():
    return TestClient(main.app)


def test_analyze_stores_and_returns(client):
    r = client.post("/api/analyze", json={"url": "http://paypa1-secure-login.xyz/verify", "deep": False})
    assert r.status_code == 200
    j = r.json()
    assert j["id"] and j["verdict"] in ("suspicious", "phishing") and j["evidence"]
    assert client.get(f"/api/scans/{j['id']}").json()["url"] == "http://paypa1-secure-login.xyz/verify"


def test_query_string_not_stored(client):
    j = client.post("/api/analyze", json={"url": "http://example.org/a?token=SECRET123", "deep": False}).json()
    stored = client.get(f"/api/scans/{j['id']}").json()
    assert "SECRET123" not in stored["url"]


@pytest.mark.parametrize("bad", ["ftp://x.com", "javascript:alert(1)", "not a url at all", "a" * 3000])
def test_invalid_input_rejected(client, bad):
    assert client.post("/api/analyze", json={"url": bad, "deep": False}).status_code in (422,)


def test_report_and_stats_and_history(client):
    j = client.post("/api/analyze", json={"url": "http://192.168.10.5/login", "deep": False}).json()
    assert client.post(f"/api/scans/{j['id']}/report", json={"status": "confirmed", "note": "ok"}).json() == {"ok": True}
    assert client.post(f"/api/scans/{j['id']}/report", json={"status": "bogus"}).status_code == 422
    assert client.post("/api/scans/999999/report", json={"status": "confirmed"}).status_code == 404
    s = client.get("/api/stats").json()
    assert s["total"] >= 3 and s["reports"] >= 1
    assert len(client.get("/api/history?limit=2").json()) == 2


def test_model_and_health(client):
    m = client.get("/api/model").json()
    if not m["loaded"]:
        pytest.skip("no trained model present (run train.py)")
    assert m["metrics"]["data_file"]
    assert client.get("/api/health").json()["status"] == "ok"


def test_security_headers(client):
    h = client.get("/api/health").headers
    assert h["x-content-type-options"] == "nosniff" and "default-src 'self'" in h["content-security-policy"]


def test_api_key_enforced(client, monkeypatch):
    monkeypatch.setenv("PHISHGUARD_API_KEY", "s3cret")
    assert client.post("/api/analyze", json={"url": "http://a.example.com", "deep": False}).status_code == 401
    ok = client.post("/api/analyze", json={"url": "http://a.example.com", "deep": False}, headers={"X-API-Key": "s3cret"})
    assert ok.status_code == 200


def test_rate_limit(client, monkeypatch):
    monkeypatch.delenv("PHISHGUARD_API_KEY", raising=False)
    main._hits.clear()
    monkeypatch.setattr(main, "RATE_LIMIT", 3)
    codes = [client.post("/api/analyze", json={"url": "http://b.example.com", "deep": False}).status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and codes[3:] == [429, 429]
