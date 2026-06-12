"""Stockage SQLite des evenements ingeres (B13)."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import threading
from typing import Any

_DB_PATH = os.environ.get("HP_DB", "/data/events.db")
_lock = threading.Lock()
# Chemin reellement utilise : bascule en fallback si /data n'est pas inscriptible.
_active_db = _DB_PATH

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id     TEXT PRIMARY KEY,
    ts           TEXT,
    service      TEXT,
    src_ip       TEXT,
    session_id   TEXT,
    action       TEXT,
    username     TEXT,
    password     TEXT,
    command      TEXT,
    http_path    TEXT,
    user_agent   TEXT,
    country      TEXT,
    country_code TEXT,
    lat          REAL,
    lon          REAL,
    abuse_score  INTEGER,
    profile      TEXT,
    confidence   REAL,
    integrity_ok INTEGER,
    raw          TEXT
);
CREATE INDEX IF NOT EXISTS idx_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_service ON events(service);
"""


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_active_db, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _try_init(path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.executescript(_SCHEMA)
    conn.commit()
    conn.close()


def init() -> None:
    """Initialise la base. Si /data n'est pas inscriptible (volume mal chown-e),
    bascule sur /tmp pour que l'API ne tombe JAMAIS en crash-loop."""
    global _active_db
    last: Exception | None = None
    for candidate in (_DB_PATH, "/tmp/honeypot-events.db"):
        try:
            _try_init(candidate)
            _active_db = candidate
            if candidate != _DB_PATH:
                print(f"[storage] WARN: {_DB_PATH} non inscriptible, bascule sur "
                      f"{candidate}. Verifie le chown 1000:1000 du volume /data.",
                      file=sys.stderr, flush=True)
            return
        except Exception as exc:  # noqa: BLE001
            last = exc
    raise last  # type: ignore[misc]


def insert_event(event: dict[str, Any], enrichment: dict[str, Any],
                 classification: dict[str, Any], integrity_ok: bool) -> None:
    http = event.get("http") or {}
    geo = enrichment.get("geo", {})
    rep = enrichment.get("reputation", {})
    with _lock:
        conn = _connect()
        conn.execute(
            "INSERT OR REPLACE INTO events VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                event.get("event_id"), event.get("timestamp"), event.get("service"),
                event.get("src_ip"), event.get("session_id"), event.get("action"),
                event.get("username"), event.get("password"), event.get("command"),
                http.get("path"), http.get("user_agent"),
                geo.get("country"), geo.get("country_code"), geo.get("lat"), geo.get("lon"),
                rep.get("abuse_score"),
                classification.get("profile"), classification.get("confidence"),
                1 if integrity_ok else 0, json.dumps(event, ensure_ascii=False),
            ),
        )
        conn.commit()
        conn.close()


def query(sql: str, params: tuple = ()) -> list[dict[str, Any]]:
    # commit() est INDISPENSABLE : query() sert aussi aux ecritures
    # (UPDATE du profil dans ingest()). Sans commit, l'UPDATE est annule a la
    # fermeture de la connexion -> profile reste NULL -> by_profile vide.
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(sql, params).fetchall()
            conn.commit()
            return [dict(row) for row in rows]
        finally:
            conn.close()


def session_events(session_id: str) -> list[dict[str, Any]]:
    rows = query("SELECT raw FROM events WHERE session_id=? ORDER BY ts", (session_id,))
    return [json.loads(r["raw"]) for r in rows]
