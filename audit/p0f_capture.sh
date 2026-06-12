#!/usr/bin/env bash
###############################################################################
# Empreinte passive de la pile TCP/IP avec p0f (critere 9 de l'audit).
#
# p0f observe le trafic et deduit l'OS REEL de la machine qui heberge le
# honeypot. C'est LA limite structurelle d'un honeypot conteneurise : p0f voit
# l'OS de l'hote Docker (le noyau Linux partage), PAS l'OS "revendique" par les
# bannieres applicatives (Debian 12). A defendre devant le jury comme limite
# connue (cf. rapport, section Limites).
#
# Prerequis : sudo apt install p0f
# Usage (root requis pour la capture) :
#   sudo bash audit/p0f_capture.sh [INTERFACE]    # defaut: loopback 'lo'
# Puis, dans un AUTRE terminal, generez du trafic :
#   bash attacks/run_all.sh
###############################################################################
set -u
IFACE="${1:-lo}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/results"
mkdir -p "$OUT"

if ! command -v p0f >/dev/null 2>&1; then
  echo "[!] p0f introuvable. Installez-le : sudo apt update && sudo apt install -y p0f"
  exit 1
fi

echo "[*] p0f sur l'interface '$IFACE' -> $OUT/p0f.log"
echo "[*] Dans un autre terminal : bash attacks/run_all.sh"
echo "[*] Ctrl+C pour arreter la capture."
p0f -i "$IFACE" -o "$OUT/p0f.log"
