# Rapport final — Honeypot Intelligent (M1SPRO)

> Squelette du rapport 15-25 pages a remettre en J5 17h. Remplir les sections.

## 1. Resume executif
(1/2 page : ce qui a ete livre, chiffres cles : nb d'evenements, score furtivite, profils)

## 2. Architecture
- Schema des composants + flux de donnees (cf. README)
- Choix techniques et justifications (cf. note-de-cadrage.md)
- Isolation reseau et durcissement Docker

## 3. Implementation des services
- SSH (asyncssh) : capture credentials + faux shell
- HTTP (FastAPI) : routes piegees + payloads CVE
- FTP (pyftpdlib) : faux filesystem
- Contrat de log `event.schema.json v1.0.0` + signature HMAC

## 4. Pipeline d'analyse
- Shipper -> API d'ingestion -> SQLite
- Enrichissement GeoIP + AbuseIPDB
- Classification 4 profils + **matrice de confusion** (precision mesuree)
- Dashboard live (captures)

## 5. Validation par attaques
- Hydra (SSH/FTP), Nikto/dirsearch (HTTP), payloads Log4Shell/Spring4Shell
- Dataset rejoue + attaques inter-equipes LAN
- Tableau : nb d'evenements captures, % classifies correctement

## 6. Audit de detectabilite
- Score initial /30 -> contre-mesures -> score final /30 (cf. stealth-audit-*.md)
- Captures avant/apres

## 7. Securite du honeypot lui-meme
- Conteneurs non-root, read-only, cap-drop ALL, no-new-privileges
- Integrite des logs (HMAC), impossibilite de pivot

## 8. Mapping MITRE ATT&CK des observations
(techniques observees + extrait des regles Sigma generees)

## 9. Cadre legal et ethique
(synthese charte RGPD / Article 323-1 / ENISA)

## 10. Retour d'experience
- Ce qui a marche / pose probleme
- Pistes d'amelioration en production reelle

## Annexes
- Exports : `iocs.json` (STIX 2.1), `rules/*.yml` (Sigma), `block_list.iptables`
- Dump anonymise des evenements
