"""Construction, signature (HMAC-SHA256) et validation des evenements honeypot.

Le contrat de log est defini dans schemas/event.schema.json (v1.0.0).
L'integrite des logs s'appuie sur M1CRYP : chaque evenement est signe avec
une cle HMAC partagee (HP_LOG_HMAC_KEY). La signature couvre le coeur de
l'evenement (hors champs 'integrity' et 'enrichment' qui sont ajoutes
respectivement par le builder et par l'analyzer).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

try:  # jsonschema est present en CI et dans les images Docker
    import jsonschema
except ImportError:  # fallback gracieux (smoke tests stdlib)
    jsonschema = None

SCHEMA_VERSION = "1.0.0"
_HMAC_KEY = os.environ.get("HP_LOG_HMAC_KEY", "ecoleit-m1spro-dev-key").encode()
_DEFAULT_LOG_DIR = os.environ.get("HP_LOG_DIR", "/logs")

_NON_SIGNED = ("integrity", "enrichment")


@lru_cache(maxsize=1)
def _schema() -> dict[str, Any]:
    path = Path(__file__).resolve().parents[2] / "schemas" / "event.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _core(event: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in event.items() if k not in _NON_SIGNED}


def sign(event: dict[str, Any]) -> str:
    """Signature HMAC-SHA256 du coeur de l'evenement."""
    return hmac.new(_HMAC_KEY, _canonical(_core(event)), hashlib.sha256).hexdigest()


def verify(event: dict[str, Any]) -> bool:
    """Verifie l'integrite d'un evenement signe."""
    integrity = event.get("integrity")
    if not integrity or "hmac" not in integrity:
        return False
    return hmac.compare_digest(integrity["hmac"], sign(event))


def make_event(
    service: str,
    src_ip: str,
    action: str,
    *,
    session_id: str | None = None,
    src_port: int | None = None,
    dst_port: int | None = None,
    username: str | None = None,
    password: str | None = None,
    command: str | None = None,
    http: dict[str, Any] | None = None,
    ftp: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Construit un evenement conforme au schema et le signe."""
    event: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": service,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "session_id": session_id or str(uuid.uuid4()),
        "action": action,
        "username": username,
        "password": password,
        "command": command,
        "http": http,
        "ftp": ftp,
        "enrichment": None,
    }
    event["integrity"] = {"alg": "HMAC-SHA256", "hmac": sign(event)}
    return event


def validate(event: dict[str, Any]) -> bool:
    """Valide l'evenement contre le JSON Schema (no-op si jsonschema absent)."""
    if jsonschema is None:
        return True
    jsonschema.validate(instance=event, schema=_schema())
    return True


def _warn(msg: str) -> None:
    print(f"[hp_common] WARN: {msg}", file=sys.stderr, flush=True)


def emit(event: dict[str, Any], log_dir: str | None = None) -> None:
    """Ecrit l'evenement en JSONL dans logs/<service>.jsonl.

    REGLE D'OR HONEYPOT : la journalisation est best-effort et ne doit JAMAIS
    faire planter un service (sinon un attaquant detecte le honeypot, et la demo
    casse). Toute erreur de validation ou d'ecriture est journalisee sur stderr
    mais n'interrompt pas le service.
    """
    try:
        validate(event)
    except Exception as exc:  # noqa: BLE001 - validation non bloquante
        _warn(f"validation echouee (log conserve quand meme): {exc}")
    try:
        target_dir = Path(log_dir or _DEFAULT_LOG_DIR)
        target_dir.mkdir(parents=True, exist_ok=True)
        line = json.dumps(event, ensure_ascii=False)
        with (target_dir / f"{event['service']}.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except Exception as exc:  # noqa: BLE001 - ecriture non bloquante
        _warn(f"ecriture du log impossible ({exc}). "
              "Verifie les droits du volume /logs (chown 1000:1000).")
