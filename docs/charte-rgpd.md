# Charte de collecte de traces d'attaque — Honeypot M1SPRO

> Conforme aux recommandations ENISA (Proactive Detection of Security Incidents — Honeypots),
> au RGPD et a l'Article 323-1 du Code penal francais.

## 1. Finalite de la collecte
Le honeypot collecte des traces techniques d'interactions non sollicitees dans un
unique but **pedagogique et de recherche en securite defensive** : analyse
comportementale d'attaquants, mesure de detectabilite, production d'indicateurs
de compromission (IOCs).

## 2. Donnees collectees
- Adresses IP source et ports
- Horodatage des connexions
- Identifiants testes (login / mot de passe) — *donnees d'attaque, pas de comptes reels*
- Commandes saisies, requetes HTTP, commandes FTP
- User-agents, bannieres, payloads

## 3. Base legale et proportionnalite
- Le systeme est **passif** : il n'attaque personne et ne sollicite aucune connexion.
- Aucune donnee n'est utilisee pour identifier nominativement une personne physique.
- Les adresses IP (donnees a caractere personnel au sens RGPD) sont traitees au titre
  de l'**interet legitime** (securite des SI), avec minimisation et duree limitee.

## 4. Cadre penal (Article 323-1)
- Le honeypot n'effectue **aucun acces frauduleux** a un STAD tiers.
- Les contre-attaques ("hack back") sont **interdites**.
- L'attaquant entre de son propre fait : pas de provocation active a l'infraction.

## 5. Duree de conservation et anonymisation
- Logs bruts : conserves 30 jours maximum dans le cadre du projet.
- Avant tout partage (rapport, MISP), les IPs sont **tronquees / anonymisees** selon
  le besoin (ex: /24) sauf necessite d'IOC.

## 6. Securite des donnees collectees
- Integrite garantie par **signature HMAC-SHA256** de chaque evenement (M1CRYP).
- Stockage isole, acces restreint a l'equipe projet.
- Conteneurs non-root, read-only, capabilities minimales (anti-pivot).

## 7. Engagement de l'equipe
Nous, signataires, nous engageons a respecter cette charte pendant toute la duree du projet.

| Role          | Nom                | Signature | Date |
|---------------|--------------------|-----------|------|
| Etudiant 1    | Mohammed Sellak    |           |      |
| Etudiant 2    |                    |           |      |
| Etudiant 3    |                    |           |      |
| Etudiant 4    |                    |           |      |

*Projet realise en configuration solo — signature unique le cas echeant.*
