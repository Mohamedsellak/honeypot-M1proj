"""Assertions de validation de la chaine de capture (B5/B10/B23).

Interroge l'API analyzer et verifie que les attaques ont bien ete capturees,
classifiees et enrichies. Sortie en code retour != 0 si la chaine est cassee
(utilisable en CI ou en demo).
"""

from __future__ import annotations

import os
import sys

try:
    import httpx
except ImportError:
    import urllib.request
    import json as _json

    class _Mini:
        @staticmethod
        def get(url, timeout=5):
            with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
                class R:
                    def json(self_inner):
                        return _json.loads(resp.read())
                return R()
    httpx = _Mini()  # type: ignore

API = os.environ.get("HP_API_URL", "http://127.0.0.1:8000")


def main() -> int:
    stats = httpx.get(f"{API}/stats").json()
    print("stats:", stats)
    checks = [
        ("au moins 50 evenements captures", stats.get("total_events", 0) >= 50),
        ("service ssh present", stats.get("by_service", {}).get("ssh", 0) > 0),
        ("service http present", stats.get("by_service", {}).get("http", 0) > 0),
        ("profil bruteforcer detecte", stats.get("by_profile", {}).get("bruteforcer", 0) > 0),
        ("integrite des logs OK", stats.get("integrity_failures", 1) == 0),
    ]
    ok = True
    for label, passed in checks:
        print(f"  [{'PASS' if passed else 'FAIL'}] {label}")
        ok = ok and passed
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
