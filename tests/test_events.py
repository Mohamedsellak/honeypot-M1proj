"""Tests du contrat de log + signature HMAC (CI: pytest)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))

from hp_common import make_event, sign, verify  # noqa: E402


def test_make_event_has_required_fields():
    ev = make_event("ssh", "1.2.3.4", "login_attempt", username="root", password="123456")
    for field in ("schema_version", "event_id", "timestamp", "service", "src_ip",
                  "session_id", "action", "integrity"):
        assert field in ev
    assert ev["schema_version"] == "1.0.0"
    assert ev["integrity"]["alg"] == "HMAC-SHA256"


def test_signature_roundtrip():
    ev = make_event("http", "8.8.8.8", "request")
    assert verify(ev) is True


def test_tamper_detected():
    ev = make_event("ssh", "1.2.3.4", "login_attempt", username="root", password="x")
    ev["password"] = "tampered"
    assert verify(ev) is False


def test_enrichment_does_not_break_integrity():
    ev = make_event("ssh", "1.2.3.4", "connect")
    ev["enrichment"] = {"geo": {"country": "France"}}
    assert verify(ev) is True  # enrichment hors signature
