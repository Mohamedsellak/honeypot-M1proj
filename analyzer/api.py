"""API d'ingestion + analyse (B13 -> B17).

Expose :
    POST /events        -> ingere un evenement (validation, integrite, enrichissement, classification)
    GET  /events        -> derniers evenements
    GET  /stats         -> KPIs pour le dashboard
    GET  /attackers     -> top IPs enrichies + profil
    GET  /exports/sigma -> regles Sigma generees
    GET  /exports/iptables -> blocklist iptables
    GET  /exports/stix  -> bundle STIX 2.1 (bonus)

Un thread de fond "tail" /logs/all-events.jsonl et ingere automatiquement.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from hp_common import verify  # noqa: E402

import storage  # noqa: E402
from classifier import BehaviorClassifier  # noqa: E402
from enrichers import enrich_geo, enrich_reputation  # noqa: E402
import exporters  # noqa: E402

LOG_FILE = Path(os.environ.get("HP_LOG_DIR", "/logs")) / "all-events.jsonl"

app = FastAPI(title="honeypot-analyzer")
_clf = BehaviorClassifier()


def ingest(event: dict[str, Any]) -> dict[str, Any]:
    integrity_ok = verify(event)
    enrichment = {
        "geo": enrich_geo(event.get("src_ip", "")),
        "reputation": enrich_reputation(event.get("src_ip", "")),
    }
    event["enrichment"] = enrichment
    storage.insert_event(event, enrichment, {"profile": None, "confidence": None}, integrity_ok)
    # (re)classifie la session complete a chaque nouvel evenement
    sess = storage.session_events(event.get("session_id", ""))
    classification = _clf.classify_session(sess)
    storage.query("UPDATE events SET profile=?, confidence=? WHERE session_id=?",
                  (classification["profile"], classification["confidence"],
                   event.get("session_id", "")))
    return {"integrity_ok": integrity_ok, "classification": classification}


@app.on_event("startup")
def _startup() -> None:
    try:
        storage.init()
    except Exception as exc:  # noqa: BLE001 - ne jamais tuer l'API au demarrage
        print(f"[analyzer] WARN: init stockage echoue: {exc}", file=sys.stderr, flush=True)
    threading.Thread(target=_tail_logs, daemon=True).start()


def _tail_logs() -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOG_FILE.touch(exist_ok=True)
    offset = 0
    while True:
        try:
            size = LOG_FILE.stat().st_size
            if size < offset:
                offset = 0
            if size > offset:
                with LOG_FILE.open("r", encoding="utf-8") as fh:
                    fh.seek(offset)
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            ingest(json.loads(line))
                        except Exception:  # noqa: BLE001
                            continue
                    offset = fh.tell()
        except FileNotFoundError:
            LOG_FILE.touch(exist_ok=True)
        time.sleep(1.0)


@app.post("/events")
async def post_event(request: Request) -> JSONResponse:
    event = await request.json()
    result = ingest(event)
    return JSONResponse(result)


@app.get("/events")
def get_events(limit: int = 100) -> list[dict[str, Any]]:
    return storage.query(
        "SELECT event_id, ts, service, src_ip, action, username, password, command, "
        "http_path, user_agent, country, country_code, lat, lon, abuse_score, profile, "
        "confidence, integrity_ok FROM events ORDER BY ts DESC LIMIT ?", (limit,))


@app.get("/stats")
def get_stats() -> dict[str, Any]:
    rows = storage.query("SELECT service, src_ip, username, password, profile, country, "
                         "action, integrity_ok FROM events")
    total = len(rows)
    by_service = Counter(r["service"] for r in rows)
    by_profile = Counter(r["profile"] for r in rows if r["profile"])
    by_country = Counter(r["country"] for r in rows if r["country"])
    creds = Counter(f"{r['username']}:{r['password']}" for r in rows
                    if r["action"] == "login_attempt" and r["username"])
    integrity_failures = sum(1 for r in rows if r["integrity_ok"] == 0)
    return {
        "total_events": total,
        "unique_ips": len({r["src_ip"] for r in rows}),
        "by_service": dict(by_service),
        "by_profile": dict(by_profile),
        "by_country": dict(by_country.most_common(15)),
        "top_credentials": creds.most_common(10),
        "integrity_failures": integrity_failures,
    }


@app.get("/attackers")
def get_attackers(limit: int = 50) -> list[dict[str, Any]]:
    return storage.query(
        "SELECT src_ip, COUNT(*) AS events, MAX(profile) AS profile, MAX(country) AS country, "
        "MAX(country_code) AS country_code, MAX(lat) AS lat, MAX(lon) AS lon, "
        "MAX(abuse_score) AS abuse_score FROM events GROUP BY src_ip "
        "ORDER BY events DESC LIMIT ?", (limit,))


@app.get("/exports/sigma", response_class=PlainTextResponse)
def export_sigma() -> str:
    return exporters.build_sigma(storage.query(
        "SELECT * FROM events WHERE profile IN ('bruteforcer','bot') LIMIT 500"))


@app.get("/exports/iptables", response_class=PlainTextResponse)
def export_iptables() -> str:
    rows = storage.query("SELECT src_ip, MAX(abuse_score) AS abuse_score, COUNT(*) AS n "
                         "FROM events GROUP BY src_ip HAVING n >= 5 OR abuse_score >= 50")
    return exporters.build_iptables([r["src_ip"] for r in rows])


@app.get("/exports/stix")
def export_stix() -> JSONResponse:
    rows = storage.query("SELECT DISTINCT src_ip, MAX(country) AS country, "
                         "MAX(abuse_score) AS abuse_score FROM events GROUP BY src_ip")
    return JSONResponse(exporters.build_stix(rows))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("HP_API_PORT", "8000")),
                log_level="warning")
