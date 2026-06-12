# Note de cadrage (2-4 pages) — Honeypot Intelligent M1SPRO

## 1. Definition et taxonomie (Spitzner)
Un **honeypot** est un systeme leurre dont toute interaction est par definition
suspecte. Taxonomie selon le **niveau d'interaction** :
- **Faible (low-interaction)** : emule quelques services, peu de risque, peu de donnees.
- **Moyen (medium-interaction)** : simule des services credibles avec un faux shell /
  fausses reponses, sans vrai OS expose — **c'est le choix de ce projet**.
- **Fort (high-interaction)** : vrai systeme sacrifie, riche mais dangereux (risque de pivot).

**Justification du medium-interaction** : meilleur ratio richesse/risque pour un projet
pedagogique — on capture credentials, commandes et payloads sans jamais exposer un
vrai OS exploitable.

## 2. Placement et finalite
- **Placement** : honeypot de recherche (analyse comportementale), deploye en local /
  LAN inter-equipes, pas en production.
- **Finalite** : production de renseignement (CTI) + entrainement a la detection (Blue Team).

## 3. Cadre de deception : MITRE Engage
Le projet s'aligne sur **MITRE Engage** (cadre officiel de la deception, successeur de
MITRE Shield). Activites mobilisees :
- *Collect* : capture des artefacts d'attaque.
- *Detect* : alertes et classification en temps reel.
- *Direct / Disrupt* : leurres (faux .env, faux fs FTP) qui orientent l'attaquant.
- *Reassure* : bannieres et faux systeme plausibles (furtivite) pour prolonger l'engagement.

## 4. Mapping MITRE ATT&CK
Les observations sont mappees sur ATT&CK : T1110 (Brute Force), T1595 (Active Scanning),
T1190 (Exploit Public-Facing Application), T1059 (Command Interpreter), T1083 (Discovery).

## 5. Architecture retenue
3 services Python conteneurises (SSH/HTTP/FTP) -> logs JSON signes -> shipper ->
API d'ingestion -> enrichissement (GeoIP + AbuseIPDB) -> classification 4 profils ->
SQLite -> dashboard live. CI/CD (ruff + bandit + semgrep + pytest + build + Trivy).

## 6. Cadre legal
Voir `charte-rgpd.md` : interet legitime (RGPD), systeme passif (Article 323-1),
anonymisation, integrite HMAC, interdiction du hack-back.

## 7. Choix techniques cles (a defendre devant le jury)
| Choix                         | Justification |
|-------------------------------|---------------|
| Medium-interaction            | Richesse sans risque de pivot |
| asyncssh / FastAPI / pyftpdlib| Stack Python imposee, async, mature |
| Logs JSON + JSON Schema       | Contrat d'interface versionne entre composants |
| Signature HMAC-SHA256         | Integrite des preuves (M1CRYP) |
| SQLite                        | Simplicite, suffisant pour le volume du projet |
| Conteneurs non-root, read-only| Durcissement NIST SP 800-190, anti-pivot |
| Classification heuristique    | Explicable, auditable, sans dataset d'entrainement |
