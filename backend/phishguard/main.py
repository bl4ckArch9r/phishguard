"""PhishGuard API + dashboard server.

    uvicorn phishguard.main:app --host 0.0.0.0 --port 8000

Endpoints
    POST /api/analyze          {url, deep?}  -> full analysis (stored in history)
    GET  /api/history          recent scans
    GET  /api/scans/{id}       one stored scan
    POST /api/scans/{id}/report {status, note?}  mark false_positive / false_negative / confirmed
    GET  /api/stats            dashboard statistics
    GET  /api/model            model + evaluation metrics + provider configuration
    GET  /api/health
Optional: set PHISHGUARD_API_KEY and send it as the X-API-Key header.
"""
from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import pipeline, storage, threat_intel
from .model_service import load_metrics

FRONTEND = Path(__file__).resolve().parent.parent.parent / "frontend"
RATE_LIMIT = int(os.environ.get("PHISHGUARD_RATE_PER_MIN", "20"))

app = FastAPI(title="PhishGuard", version="1.0", docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")
storage.init()

_hits: dict[str, deque] = defaultdict(deque)


def guard(request: Request):
    key = os.environ.get("PHISHGUARD_API_KEY")
    if key and request.headers.get("x-api-key") != key:
        raise HTTPException(401, "Missing or invalid API key")
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    q = _hits[ip]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        raise HTTPException(429, f"Rate limit: {RATE_LIMIT} scans per minute")
    q.append(now)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if not request.url.path.startswith("/api/docs") and not request.url.path.startswith("/api/openapi"):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; connect-src 'self'; frame-ancestors 'none'")
    return resp


class AnalyzeIn(BaseModel):
    url: str = Field(min_length=3, max_length=2048)
    deep: bool = True


class ReportIn(BaseModel):
    status: str = Field(pattern="^(false_positive|false_negative|confirmed)$")
    note: str | None = Field(default=None, max_length=500)


@app.post("/api/analyze", dependencies=[Depends(guard)])
async def analyze(body: AnalyzeIn):
    try:
        result = await pipeline.analyze(body.url, deep=body.deep)
    except pipeline.InvalidURL as e:
        raise HTTPException(422, str(e))
    result["id"] = storage.save(result)
    return result


@app.get("/api/history")
def history(limit: int = 50):
    return storage.history(min(max(limit, 1), 200))


@app.get("/api/scans/{scan_id}")
def scan(scan_id: int):
    r = storage.get(scan_id)
    if not r:
        raise HTTPException(404, "Scan not found")
    return r


@app.post("/api/scans/{scan_id}/report", dependencies=[Depends(guard)])
def report(scan_id: int, body: ReportIn):
    if not storage.set_report(scan_id, body.status, body.note):
        raise HTTPException(404, "Scan not found")
    return {"ok": True}


@app.get("/api/stats")
def stats():
    return storage.stats()


@app.get("/api/model")
def model_info():
    m = pipeline.MODEL
    providers = {
        "local_feed": {"configured": threat_intel.feed_size() > 0, "entries": threat_intel.feed_size()},
        "virustotal": {"configured": bool(os.environ.get("VIRUSTOTAL_API_KEY"))},
        "safe_browsing": {"configured": bool(os.environ.get("GOOGLE_SAFE_BROWSING_KEY"))},
        "urlhaus": {"configured": bool(os.environ.get("URLHAUS_AUTH_KEY"))},
    }
    return {
        "loaded": m is not None,
        "name": m.name if m else None,
        "trained_on": m.trained_on if m else None,
        "version": m.version if m else None,
        "metrics": load_metrics(),
        "providers": providers,
    }


@app.get("/api/health")
def health():
    return {"status": "ok", "model_loaded": pipeline.MODEL is not None}


@app.exception_handler(Exception)
async def unhandled(_, exc):
    return JSONResponse({"detail": "Internal error while analysing that link"}, status_code=500)


if FRONTEND.exists():
    app.mount("/static", StaticFiles(directory=FRONTEND), name="static")

    @app.get("/")
    def index():
        return FileResponse(FRONTEND / "index.html")
