# Honeypot Intelligent — M1SPRO (ECOLEIT)

Honeypot multi-services (SSH + HTTP + FTP) en Python, conteneurisé via Docker Compose,
avec pipeline d'analyse comportementale (classification en 4 profils), enrichissement
GeoIP/AbuseIPDB, dashboard live, scripts d'attaque, audit de détectabilité et exports
STIX/Sigma.

> Projet construit en mode **solo / 15h**. Tout est conçu pour qu'un seul `docker compose up`
> relance la stack complète en < 5 minutes sur une machine vierge.

## Démarrage rapide (TL;DR)

```bash
# 1. Lancer toute la stack
docker compose up --build -d

# 2. Vérifier que tout tourne
docker compose ps

# 3. Ouvrir le dashboard
xdg-open http://localhost:8050      # Linux
# http://localhost:8050 sur Windows/Mac

# 4. Attaquer le honeypot (depuis la racine du repo)
bash attacks/run_all.sh

# 5. Vérifier que la chaîne de capture marche
python3 attacks/assertions.py
```

## Architecture (flux de données)

```
[Attaquant / Kali]
   | Hydra / Nikto / dirsearch / commandes manuelles
   v
[honeypot-ssh:2222] [honeypot-http:8080] [honeypot-ftp:2121]
   |  ecrivent des evenements JSON signes (HMAC-SHA256)
   v   /logs/{ssh,http,ftp}.jsonl
[shipper]  -- agrege --> /logs/all-events.jsonl
   v
[analyzer]  ingestion (tail) -> validation schema -> verif integrite
            -> enrichissement (GeoIP + AbuseIPDB) -> classification 4 profils
            -> stockage SQLite (/data/events.db)
            API: POST /events, GET /events, GET /stats, GET /attackers, GET /exports/*
   v
[dashboard:8050]  KPI cards + carte geo + time-series + camembert des profils
```

## Ports exposes

| Service        | Port hote | Role                                  |
|----------------|-----------|---------------------------------------|
| honeypot-ssh   | 2222      | Faux serveur SSH (asyncssh)           |
| honeypot-http  | 8080      | Faux serveur HTTP (FastAPI)           |
| honeypot-ftp   | 2121      | Faux serveur FTP (pyftpdlib)          |
| analyzer       | 8000      | API d'ingestion + analyse             |
| dashboard      | 8050      | Dashboard live (Plotly Dash)          |

## Les 4 profils attaquants (classification heuristique)

| Profil               | Signature principale                                              |
|----------------------|-------------------------------------------------------------------|
| `bruteforcer`        | Beaucoup de `login_attempt` SSH/FTP dans une session courte        |
| `bot`               | UA automatise (curl, python-requests, zgrab...) + paths d'exploit  |
| `human`             | Commandes shell interactives variees, rythme lent                  |
| `scanner_legitimate` | Scanner Internet connu (Shodan, Censys, GreyNoise), 1 requete GET  |

Seuils chiffres : voir `analyzer/profiles.json`.

## Cadre legal

Voir `docs/charte-rgpd.md` (charte de collecte RGPD / Article 323-1 / ENISA) et
`docs/note-de-cadrage.md` (justification theorique des choix de conception).

## Structure

```
honeypot-m1spro/
├── docker-compose.yml
├── pyproject.toml
├── schemas/event.schema.json        # contrat de log v1.0.0
├── common/hp_common/                # event builder + signature + shipper
├── honeypots/{ssh,http,ftp}/        # les 3 services
├── shipper/                         # agregation des logs
├── analyzer/                        # API + classifier + enrichers + exports
├── dashboard/                       # Dash live
├── attacks/                         # scripts d'attaque + assertions
├── datasets/                        # rockyou-top1000, user-agents, payloads CVE
├── tests/                           # tests pytest (CI)
└── docs/                            # charte, note de cadrage, audits furtivite
```
# honeypot-M1proj
