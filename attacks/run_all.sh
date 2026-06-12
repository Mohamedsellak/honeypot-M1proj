#!/usr/bin/env bash
# Synchronisation fin J2 : 'attacks/run_all.sh' depuis Kali -> tous les services
# capturent en moins de 5 min. Enchaine SSH + HTTP + FTP.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
HOST="${HOST:-127.0.0.1}"

echo "==== [1/3] SSH bruteforce ===="
bash "$HERE/run_ssh_bruteforce.sh" "$HOST" "${SSH_PORT:-2222}"
echo "==== [2/3] HTTP scan ===="
bash "$HERE/run_http_scan.sh" "http://$HOST:${HTTP_PORT:-8080}"
echo "==== [3/3] FTP bruteforce ===="
bash "$HERE/run_ftp_brute.sh" "$HOST" "${FTP_PORT:-2121}"
echo "==== Termine. Validation: python3 $HERE/assertions.py ===="
