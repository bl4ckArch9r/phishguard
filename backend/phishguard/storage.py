"""SQLite persistence for scan history, statistics and user reports.

Privacy: the stored URL has its query string and fragment removed, because
those commonly carry session tokens or personal identifiers.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

DB_PATH = Path(os.environ.get("PHISHGUARD_DB", Path(__file__).resolve().parent.parent / "data" / "phishguard.db"))
_lock = threading.Lock()


def _conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init():
    with _lock, _conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            url TEXT NOT NULL,
            registered_domain TEXT,
            verdict TEXT NOT NULL,
            score INTEGER NOT NULL,
            confidence REAL,
            duration_ms INTEGER,
            deep INTEGER,
            result_json TEXT NOT NULL,
            report_status TEXT,
            report_note TEXT)""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_scans_ts ON scans(ts)")


def _strip(url: str) -> str:
    p = urlsplit(url)
    return p._replace(query="", fragment="").geturl()[:300]


def save(result: dict) -> int:
    stored = dict(result)
    stored.pop("preview", None)   # screenshots are shown once, never stored
    stored["url"] = _strip(result["url"])
    with _lock, _conn() as c:
        cur = c.execute(
            "INSERT INTO scans(ts,url,registered_domain,verdict,score,confidence,duration_ms,deep,result_json)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"), stored["url"],
             result.get("registered_domain"), result["verdict"], result["score"],
             result.get("confidence"), result.get("duration_ms"), int(bool(result.get("deep"))),
             json.dumps(stored)))
        return cur.lastrowid


def get(scan_id: int):
    with _lock, _conn() as c:
        r = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not r:
        return None
    out = json.loads(r["result_json"])
    out["id"], out["ts"] = r["id"], r["ts"]
    out["report_status"], out["report_note"] = r["report_status"], r["report_note"]
    return out


def history(limit: int = 50):
    with _lock, _conn() as c:
        rows = c.execute("SELECT id,ts,url,registered_domain,verdict,score,confidence,report_status "
                         "FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def set_report(scan_id: int, status: str, note: str | None):
    with _lock, _conn() as c:
        cur = c.execute("UPDATE scans SET report_status=?, report_note=? WHERE id=?",
                        (status, (note or "")[:500], scan_id))
        return cur.rowcount > 0


def stats(days: int = 14):
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    with _lock, _conn() as c:
        total = c.execute("SELECT COUNT(*) n FROM scans").fetchone()["n"]
        by_v = {r["verdict"]: r["n"] for r in c.execute(
            "SELECT verdict, COUNT(*) n FROM scans GROUP BY verdict")}
        daily = c.execute(
            "SELECT substr(ts,1,10) d, verdict, COUNT(*) n FROM scans WHERE ts>=? GROUP BY d, verdict ORDER BY d",
            (since,)).fetchall()
        top = c.execute(
            "SELECT registered_domain d, COUNT(*) n, MAX(score) s FROM scans "
            "WHERE verdict!='safe' AND registered_domain IS NOT NULL GROUP BY d ORDER BY n DESC, s DESC LIMIT 8").fetchall()
        avg = c.execute("SELECT AVG(duration_ms) a FROM scans").fetchone()["a"]
        reported = c.execute("SELECT COUNT(*) n FROM scans WHERE report_status IS NOT NULL").fetchone()["n"]
    trend = {}
    for r in daily:
        trend.setdefault(r["d"], {"safe": 0, "suspicious": 0, "phishing": 0})[r["verdict"]] = r["n"]
    return {
        "total": total,
        "by_verdict": {"safe": by_v.get("safe", 0), "suspicious": by_v.get("suspicious", 0),
                       "phishing": by_v.get("phishing", 0)},
        "trend": [{"date": d, **v} for d, v in sorted(trend.items())],
        "top_flagged_domains": [{"domain": r["d"], "count": r["n"], "max_score": r["s"]} for r in top],
        "avg_duration_ms": round(avg) if avg else None,
        "reports": reported,
    }
