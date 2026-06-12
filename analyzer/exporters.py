"""Generation automatique d'exports defensifs (B17 + B24 bonus).

- block_list.iptables : regles de blocage des IPs critiques
- regles Sigma (.yml) a partir des sessions critiques
- bundle STIX 2.1 (indicateurs ipv4-addr) pour push MISP
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any


def build_iptables(ips: list[str]) -> str:
    lines = ["# block_list.iptables - genere automatiquement par l'analyzer honeypot",
             "# usage: iptables-restore < block_list.iptables (ou boucle iptables -A)"]
    for ip in sorted(set(filter(None, ips))):
        lines.append(f"-A INPUT -s {ip} -j DROP")
    return "\n".join(lines) + "\n"


def build_sigma(rows: list[dict[str, Any]]) -> str:
    """Une regle Sigma generique par profil observe."""
    profiles = {r.get("profile") for r in rows if r.get("profile")}
    blocks = []
    for profile in sorted(profiles):
        ips = sorted({r["src_ip"] for r in rows if r.get("profile") == profile and r.get("src_ip")})
        rule = f"""title: Honeypot - activite {profile}
id: {uuid.uuid4()}
status: experimental
description: Genere automatiquement depuis les sessions honeypot classees '{profile}'.
logsource:
  product: honeypot
  service: multi
detection:
  selection:
    src_ip:
{chr(10).join(f"      - '{ip}'" for ip in ips[:50])}
  condition: selection
level: {'high' if profile in ('bruteforcer', 'bot') else 'medium'}
tags:
  - attack.t1110
  - attack.t1595
"""
        blocks.append(rule)
    return "\n---\n".join(blocks) if blocks else "# aucune session critique pour le moment\n"


def build_stix(rows: list[dict[str, Any]]) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    objects: list[dict[str, Any]] = []
    for row in rows:
        ip = row.get("src_ip")
        if not ip:
            continue
        score = row.get("abuse_score") or 0
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "name": f"Honeypot source {ip}",
            "description": f"IP observee par le honeypot (pays={row.get('country')}, "
                           f"abuse_score={score}).",
            "indicator_types": ["malicious-activity"],
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "valid_from": now,
            "confidence": int(score),
        })
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
