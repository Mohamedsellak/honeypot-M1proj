#!/usr/bin/env bash
###############################################################################
# Audit de detectabilite - Honeypot M1SPRO (B18 etat initial / B22 etat final)
#
# Sonde les 3 services, capture les bannieres, lance nmap -sV + scripts NSE,
# mesure la latence des reponses, et range tout dans audit/results/.
#
# Prerequis (Kali) : nmap (fournit ncat), curl, python3.
# Usage :
#   bash audit/run_audit.sh                 # cible 127.0.0.1, ports par defaut
#   bash audit/run_audit.sh 192.168.1.50    # cible une autre IP (LAN inter-equipes)
###############################################################################
set -u

HOST="${1:-127.0.0.1}"
SSH_PORT="${HP_SSH_PORT:-2222}"
HTTP_PORT="${HP_HTTP_PORT:-8080}"
FTP_PORT="${HP_FTP_PORT:-2121}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/results"
mkdir -p "$OUT"

echo "==================================================================="
echo " Audit honeypot -> $HOST  (ssh:$SSH_PORT http:$HTTP_PORT ftp:$FTP_PORT)"
echo " Resultats : $OUT/"
echo "==================================================================="

# 1) Banniere SSH ------------------------------------------------------------
echo "[*] [1] Banniere SSH..."
( printf '\n' | timeout 5 ncat "$HOST" "$SSH_PORT" 2>/dev/null | head -1 ) > "$OUT/ssh_banner.txt"
cat "$OUT/ssh_banner.txt"

# 2) Banniere + en-tetes HTTP ------------------------------------------------
echo "[*] [2] En-tetes HTTP..."
curl -s -D - -o /dev/null "http://$HOST:$HTTP_PORT/" > "$OUT/http_headers.txt"
grep -iE "^(Server|X-Powered-By):" "$OUT/http_headers.txt" || echo "    (aucun en-tete Server/X-Powered-By)"

# 3) Banniere FTP ------------------------------------------------------------
echo "[*] [3] Banniere FTP..."
( timeout 5 ncat "$HOST" "$FTP_PORT" 2>/dev/null | head -1 ) > "$OUT/ftp_banner.txt"
cat "$OUT/ftp_banner.txt"

# 4) nmap -sV (detection de version) ----------------------------------------
echo "[*] [4] nmap -sV..."
nmap -sV -Pn -p "$SSH_PORT,$HTTP_PORT,$FTP_PORT" "$HOST" > "$OUT/nmap_sv.txt" 2>&1
grep -E "open|VERSION|Service" "$OUT/nmap_sv.txt" || true

# 5) Scripts NSE pertinents --------------------------------------------------
echo "[*] [5] nmap NSE (banner, ssh2-enum-algos, ssh-hostkey, http-headers, ftp-*)..."
nmap -Pn -p "$SSH_PORT,$HTTP_PORT,$FTP_PORT" \
  --script "banner,ssh2-enum-algos,ssh-hostkey,http-headers,http-server-header,ftp-syst,ftp-anon" \
  "$HOST" > "$OUT/nmap_nse.txt" 2>&1
echo "    -> $OUT/nmap_nse.txt"

# 6) Latence / jitter HTTP (10 requetes) -------------------------------------
echo "[*] [6] Mesure de latence HTTP (10 requetes)..."
: > "$OUT/latency_http.txt"
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "%{time_total}\n" "http://$HOST:$HTTP_PORT/" >> "$OUT/latency_http.txt"
done
cat "$OUT/latency_http.txt"

# 7) Sonde manuelle du faux shell (rappel) -----------------------------------
cat > "$OUT/_manual_checks.txt" <<'TXT'
VERIFICATIONS MANUELLES (cocher pendant la demo) :
  ssh root@HOST -p 2222   (mot de passe : 123456)
    uname -a            -> Linux srv-prod-debian 6.1.0-18-amd64 ... Debian 6.1.76-1
    cat /etc/os-release -> Debian GNU/Linux 12 (bookworm)
    id / whoami / ps aux / netstat / history / cat /etc/passwd
    -> mesurer le delai de reponse (jitter 50-300 ms attendu)
TXT
echo "    -> $OUT/_manual_checks.txt"

echo "==================================================================="
echo " Termine. Etapes suivantes :"
echo "   python3 audit/score.py          # calcule le score /30"
echo "   sudo bash audit/p0f_capture.sh  # empreinte passive TCP/IP (critere 9)"
echo "==================================================================="
