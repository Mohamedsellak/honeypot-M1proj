"""Enrichissement GeoIP (B15) via base offline MaxMind GeoLite2.

Fallback gracieux : si la base .mmdb n'est pas presente (HP_GEOIP_DB), retourne
des champs nuls -> la stack tourne meme sans la base distribuee en J1.
"""

from __future__ import annotations

import ipaddress
import os
from functools import lru_cache
from typing import Any

try:
    import maxminddb
except ImportError:
    maxminddb = None

_DB_PATH = os.environ.get("HP_GEOIP_DB", "/data/GeoLite2-City.mmdb")


@lru_cache(maxsize=1)
def _reader():
    if maxminddb is None or not os.path.exists(_DB_PATH):
        return None
    try:
        return maxminddb.open_database(_DB_PATH)
    except Exception:  # noqa: BLE001
        return None


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def enrich_geo(ip: str) -> dict[str, Any]:
    if _is_private(ip):
        return {"country": "LAN", "country_code": "--", "city": None, "lat": None, "lon": None}
    reader = _reader()
    if reader is None:
        return {"country": None, "country_code": None, "city": None, "lat": None, "lon": None}
    try:
        rec = reader.get(ip) or {}
    except Exception:  # noqa: BLE001
        rec = {}
    country = (rec.get("country") or {}).get("names", {}).get("en")
    code = (rec.get("country") or {}).get("iso_code")
    city = (rec.get("city") or {}).get("names", {}).get("en")
    loc = rec.get("location") or {}
    return {
        "country": country,
        "country_code": code,
        "city": city,
        "lat": loc.get("latitude"),
        "lon": loc.get("longitude"),
    }
