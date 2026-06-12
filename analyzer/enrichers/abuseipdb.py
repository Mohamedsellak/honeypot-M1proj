"""Enrichissement reputation IP via AbuseIPDB (B15).

- Cache local SQLite (TTL 24h) pour respecter les quotas du tier gratuit.
- Throttling 1 req/sec.
- Fallback gracieux : sans cle API (HP_ABUSEIPDB_KEY) ou hors-ligne, retourne
  un score nul sans casser le pipeline.
"""

from __future__ import annotations

import ipaddress
import os
import sqlite3
import threading
import time
from typing import Any

try:
    import httpx
except ImportError:
    httpx = None

_API_KEY = os.environ.get("HP_ABUSEIPDB_KEY", "")
_CACHE_DB = os.environ.get("HP_ABUSE_CACHE", "/data/abuse_cache.db")
_TTL = 24 * 3600
_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"

_lock = threading.Lock()
_last_call = 0.0


def _cache():
    conn = sqlite3.connect(_CACHE_DB)
    conn.execute("CREATE TABLE IF NOT EXISTS abuse (ip TEXT PRIMARY KEY, score INTEGER, "
                 "total INTEGER, ts REAL)")
    return conn


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_reserved)
    except ValueError:
        return False


def enrich_reputation(ip: str) -> dict[str, Any]:
    default = {"abuse_score": None, "total_reports": None, "source": "none"}
    if not _is_public(ip):
        return {"abuse_score": 0, "total_reports": 0, "source": "private"}

    conn = _cache()
    try:
        row = conn.execute("SELECT score, total, ts FROM abuse WHERE ip=?", (ip,)).fetchone()
        if row and (time.time() - row[2]) < _TTL:
            return {"abuse_score": row[0], "total_reports": row[1], "source": "cache"}

        if not _API_KEY or httpx is None:
            return default

        global _last_call
        with _lock:
            delta = time.time() - _last_call
            if delta < 1.0:
                time.sleep(1.0 - delta)
            _last_call = time.time()

        try:
            resp = httpx.get(
                _ENDPOINT,
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": _API_KEY, "Accept": "application/json"},
                timeout=5.0,
            )
            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore")
            total = data.get("totalReports")
        except Exception:  # noqa: BLE001
            return default

        conn.execute("INSERT OR REPLACE INTO abuse VALUES (?,?,?,?)",
                     (ip, score, total, time.time()))
        conn.commit()
        return {"abuse_score": score, "total_reports": total, "source": "abuseipdb"}
    finally:
        conn.close()
