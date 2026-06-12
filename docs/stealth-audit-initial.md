# Audit de detectabilite - ETAT INITIAL (B18)

> Etat de reference : honeypot "nu", AVANT contre-mesures de furtivite. Memes
> outils que l'audit final (B22) pour une comparaison stricte.

## Methodologie
Outils : `nmap -sV` + scripts NSE (`banner`, `ssh2-enum-algos`, `http-headers`,
`ftp-syst`, `ftp-anon`), `p0f` (empreinte passive), Honeyscore Shodan (si expose),
mesure de latence (`curl -w`) et exploration manuelle du shell. Toutes les sondes
sont automatisees par `audit/run_audit.sh` puis chiffrees par `audit/score.py`.

Direction du score : **0 = honeypot trivialement detectable, 3 = indiscernable**
d'un service reel sur la duree d'un audit court (~10 min).

## Grille de score /30 (10 criteres x 0-3)

| # | Critere | Outil | Score /3 | Ce qui trahit le honeypot |
|---|---------|-------|:--------:|---------------------------|
| 1 | Banniere SSH | nmap -sV | **0** | Banniere par defaut `SSH-2.0-AsyncSSH_2.x` : signature 100% honeypot Python |
| 2 | Banniere HTTP (Server) | curl -I | **1** | `server: uvicorn` + absence d'en-tetes Apache -> stack Python evidente |
| 3 | Banniere FTP | nmap -sV | **1** | `220 pyftpdlib ... ready` : librairie honeypot connue |
| 4 | Coherence uname / OS | shell | **0** | Pas de faux shell -> aucune coherence possible |
| 5 | Faux filesystem | exploration | **0** | Inexistant |
| 6 | Latence / jitter | curl -w | **1** | Reponses instantanees et uniformes (sigma~0) -> comportement machine |
| 7 | NSE ssh-* | nmap NSE | **0** | Algorithmes/host-key atypiques, pas d'exec/sftp -> detecte |
| 8 | NSE http-* / fingerprint | nmap NSE | **1** | Fingerprint incoherent avec un vrai Apache |
| 9 | Empreinte TCP/IP | p0f | **1** | OS hote visible (limite conteneur, non corrigeable cote appli) |
| 10| Honeyscore Shodan | honeyscore | **1** | N/A en LAN (pas d'exposition publique) - note neutre |

**SCORE INITIAL : 6 / 30**

## Observations
- Les trois bannieres applicatives par defaut suffisent a un attaquant pour
  identifier un honeypot Python en moins d'une minute (`nmap -sV`).
- L'absence de shell interactif fait echouer toute exploration : une simple
  commande `uname -a` ne renvoie rien de credible.
- Les temps de reponse parfaitement constants (jitter quasi nul) sont un
  marqueur classique de service emule.
- Seuls les criteres structurels (pile TCP/IP, exposition publique) ne dependent
  pas du durcissement applicatif et restent stables entre les deux audits.

## Commandes de reference
```bash
bash audit/run_audit.sh 127.0.0.1
nmap -sV -Pn -p 2222,8080,2121 127.0.0.1
nmap -Pn -p 2222 --script banner,ssh2-enum-algos 127.0.0.1
curl -I http://127.0.0.1:8080/
python3 audit/score.py
```
