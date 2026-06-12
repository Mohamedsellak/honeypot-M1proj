# Audit de detectabilite (B18 / B22)

Objectif : mesurer a quel point le honeypot est **identifiable comme tel**, avant
et apres les contre-mesures de furtivite, et chiffrer l'amelioration sur **30 points**.

## Contenu

| Fichier | Role |
|---------|------|
| `run_audit.sh` | Sonde les 3 services (bannieres, nmap -sV, NSE, latence) -> `results/` |
| `p0f_capture.sh` | Empreinte passive de la pile TCP/IP (critere 9) |
| `score.py` | Calcule le score /30 (auto pour les bannieres + grille documentee) -> `results/score.md` |
| `results/` | Sorties brutes + `score.md` / `score.json` (cree a l'execution) |

## Procedure

```bash
# 1. La stack doit tourner
docker compose up -d

# 2. Sondes actives (nmap, curl, bannieres, latence)
bash audit/run_audit.sh                # ou: bash audit/run_audit.sh <IP_LAN>

# 3. (optionnel) Empreinte passive TCP/IP
sudo apt install -y p0f
sudo bash audit/p0f_capture.sh lo &     # puis: bash attacks/run_all.sh

# 4. Score /30
python3 audit/score.py
```

## Interpretation

- **Score initial 6/30** : honeypot "nu" (bannieres par defaut asyncssh/uvicorn/pyftpdlib,
  pas de faux shell, reponses instantanees) -> trivialement detectable.
- **Score final 21/30** : bannieres realistes (OpenSSH/Apache/vsFTPd), faux filesystem,
  jitter 50-300 ms -> credible pour un audit court.
- **Limites assumees** (criteres 9-10) : la pile TCP/IP (p0f) trahit l'OS hote, et
  Honeyscore exige une exposition publique. Voir `docs/stealth-audit-final.md`.

Les rapports rediges (avant / apres, avec justification de chaque note) sont dans
`docs/stealth-audit-initial.md` et `docs/stealth-audit-final.md`.
