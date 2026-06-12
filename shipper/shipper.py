"""Log shipper (B11) : agrege ssh.jsonl + http.jsonl + ftp.jsonl en un flux unique.

Solution maison Python (pas de dependance externe) : tail -F des fichiers par
service, ecrit chaque nouvelle ligne dans /logs/all-events.jsonl.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

LOG_DIR = Path(os.environ.get("HP_LOG_DIR", "/logs"))
SERVICES = ["ssh", "http", "ftp", "telnet"]
OUT = LOG_DIR / "all-events.jsonl"


def main() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    offsets: dict[str, int] = {svc: 0 for svc in SERVICES}
    OUT.touch(exist_ok=True)
    print(f"[shipper] aggregating {SERVICES} -> {OUT}", flush=True)
    while True:
        with OUT.open("a", encoding="utf-8") as out:
            for svc in SERVICES:
                src = LOG_DIR / f"{svc}.jsonl"
                if not src.exists():
                    continue
                size = src.stat().st_size
                if size < offsets[svc]:  # fichier tronque/rotate
                    offsets[svc] = 0
                if size > offsets[svc]:
                    with src.open("r", encoding="utf-8") as fh:
                        fh.seek(offsets[svc])
                        for line in fh:
                            if line.strip():
                                out.write(line if line.endswith("\n") else line + "\n")
                        offsets[svc] = fh.tell()
        time.sleep(1.0)


if __name__ == "__main__":
    main()
