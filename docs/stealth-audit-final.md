# Audit de detectabilite - ETAT FINAL (B22)

> Etat APRES contre-mesures (B19/B20/B21). Memes outils et meme grille que
> l'audit initial (B18) pour une comparaison stricte.

## Contre-mesures appliquees
- **B19 - Bannieres plausibles** : `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3`,
  `Server: Apache/2.4.57 (Debian)` + `X-Powered-By: PHP/8.1.2`, `220 (vsFTPd 3.0.5)`.
  Cote HTTP, `server_header=False` (uvicorn) puis reinjection du `Server` Apache
  via middleware -> aucune fuite de la stack reelle.
- **B20 - Faux filesystem riche** : `/etc/passwd`, `/etc/os-release`, `/proc/cpuinfo`,
  `.bash_history` (10+ commandes plausibles), `ps aux`, `netstat`, `who`, `last`,
  faux home `admin`. Cote FTP : leurres `secrets.txt`, `db_dump.sql`, `backup.zip`.
- **B21 - Reponses contextuelles** : faux shell coherent (hostname `srv-prod-debian`,
  noyau Debian 6.1.76) + **jitter aleatoire 50-300 ms** sur chaque commande shell.

## Grille de score /30 (memes criteres que B18)

| # | Critere | Initial | Final | Delta | Justification de la note finale |
|---|---------|:------:|:----:|:----:|---------------------------------|
| 1 | Banniere SSH | 0 | **3** | +3 | Identique a une vraie Debian 12 ; `nmap -sV` conclut "OpenSSH 9.2p1 Debian" |
| 2 | Banniere HTTP | 1 | **3** | +2 | `Apache/2.4.57 (Debian)` + `X-Powered-By: PHP/8.1.2`, stack Python masquee |
| 3 | Banniere FTP | 1 | **3** | +2 | `220 (vsFTPd 3.0.5)`, indiscernable d'un vsFTPd reel a la banniere |
| 4 | Coherence uname / OS | 0 | **2** | +2 | `uname -a` et `/etc/os-release` concordent (Debian 12 bookworm) ; -1 : date de login figee |
| 5 | Faux filesystem | 0 | **2** | +2 | Fichiers cles credibles ; -1 : arborescence limitee, `cd` non strictement valide |
| 6 | Latence / jitter | 1 | **2** | +1 | Jitter 50-300 ms sur le shell ; -1 : reponses HTTP encore quasi instantanees |
| 7 | NSE ssh-* | 0 | **2** | +2 | Shell credible ; -1 : pas de SFTP/exec channel, host-key RSA generee a chaud |
| 8 | NSE http-* / fingerprint | 1 | **2** | +1 | En-tetes coherents ; -1 : manque ETag/Last-Modified/Accept-Ranges d'un vrai Apache |
| 9 | Empreinte TCP/IP (p0f) | 1 | **1** | 0 | **Limite assumee** : p0f voit l'OS hote Docker, non corrigeable cote appli |
| 10| Honeyscore Shodan | 1 | **1** | 0 | **Non applicable** : pas d'exposition publique en environnement LAN |

**SCORE INITIAL : 6 / 30  ->  SCORE FINAL : 21 / 30  (amelioration : +15 points)**

## Conclusion
- Le durcissement applicatif (B19-B21) fait passer le honeypot de
  *"trivialement detectable"* (6/30) a *"credible pour un audit court"* (21/30),
  soit **+15 points**, porte par les bannieres (criteres 1-3) et le faux shell.
- Les **2 points non gagnes** (criteres 9-10) sont structurels et **assumes** :
  - p0f / empreinte TCP/IP : ne depend pas de l'application mais du noyau de l'hote.
    Mitigation en production reelle : tuning `sysctl` (TTL, MSS), passerelle dediee.
  - Honeyscore : ne se mesure qu'avec une IP publique exposee ; hors perimetre
    pedagogique (LAN inter-equipes).
- **Plan d'amelioration en production** : ajouter ETag/Last-Modified cote HTTP,
  persister la host-key SSH, enrichir l'arborescence du faux shell, normaliser le
  TTL reseau. Objectif realiste : 25-26/30 sans exposer de vrai OS.

## Captures a inserer (avant / apres, cote a cote)
- `audit/results/ssh_banner.txt`, `http_headers.txt`, `ftp_banner.txt`
- `audit/results/nmap_sv.txt`, `nmap_nse.txt`
- `audit/results/latency_http.txt`, `p0f.log`
- `audit/results/score.md` (tableau genere automatiquement)
