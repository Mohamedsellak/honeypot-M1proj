# Mon discours - a lire pour le jury (francais simple)

> Projet realise par Mohammed Sellak et Rachid Oubenazha.
> Conseil : parlez lentement. Phrases courtes. Vous pouvez lire ce texte.
> Chaque partie = 1 slide. Total : environ 6 a 8 minutes.
> Repartition possible : Mohammed presente les slides, Rachid lance la demo.

---

## Slide 1 - Titre
Bonjour. Nous sommes Mohammed et Rachid.
Nous vous presentons notre projet : un honeypot.
Un honeypot, c'est un piege pour attraper les pirates.

## Slide 2 - C'est quoi un honeypot
Le mot honeypot veut dire "pot de miel".
Le miel attire les insectes.
Mon faux serveur attire les pirates.
Le pirate croit que c'est une vraie machine. Mais c'est un piege.
Je regarde tout ce qu'il fait, sans danger.

## Slide 3 - Pourquoi
Pourquoi faire ca ? Pour trois raisons.
Un : pour voir les vraies attaques et comprendre comment les pirates travaillent.
Deux : c'est sans risque. Le vrai serveur n'est jamais touche.
Trois : je garde les preuves. Ca aide a mieux se defendre.

## Slide 4 - Les 3 services
Mon piege a trois portes.
La premiere, SSH : la connexion a distance. Je note les mots de passe essayes.
La deuxieme, HTTP : un faux site web. Je note les pages que le pirate cherche.
La troisieme, FTP : un faux partage de fichiers, avec des appats.
Plus j'ai de portes, plus j'attrape de pirates.

## Slide 5 - Comment ca marche
Il y a quatre etapes simples.
Un : le piege recoit l'attaque.
Deux : j'enregistre chaque action.
Trois : j'analyse. Je regarde qui c'est et d'ou il vient.
Quatre : j'affiche tout sur un tableau de bord, en direct.
Tout est automatique.

## Slide 6 - On reconnait le pirate
Mon programme reconnait tout seul le type de pirate. Il y a quatre types.
Le bruteforcer : il essaie beaucoup de mots de passe, tres vite.
Le bot : un robot automatique.
L'humain : une vraie personne qui tape des commandes.
Le scanner connu : un robot legitime, comme Shodan.

## Slide 7 - Tableau de bord
Voici le tableau de bord. C'est une page web.
Elle montre tout en direct : le nombre d'attaques, les pays, et les types de pirates.

## Slide 8 - Les tests
Est-ce que ca marche ? Oui, je l'ai prouve.
J'ai attaque mon propre piege avec de vrais outils : Hydra et Nikto.
Resultat : plus de cinq mille attaques captees.
Et mes cinq tests automatiques passent : cinq sur cinq.

## Slide 9 - Le piege est-il credible
Un bon piege ne doit pas se voir.
J'ai teste avant et apres mes ameliorations.
Avant : six sur trente. On voyait que c'etait un faux.
Apres : vingt-et-un sur trente. Plus quinze points.
Maintenant mon faux serveur ressemble bien plus a un vrai.

## Slide 10 - Securite et loi
Deux points importants.
La securite : le piege est enferme dans des conteneurs Docker. Le pirate ne peut pas sortir.
La loi : je n'attaque personne, et je respecte le RGPD. J'anonymise les adresses.
La regle d'or : un honeypot observe, il ne riposte jamais.

## Slide 11 - Conclusion
Pour conclure.
J'ai fait un piege a trois services qui attrape les pirates.
Une analyse automatique : qui, d'ou, quel type.
Tout est teste et prouve.
Et c'est securise et legal.

## Slide 12 - Merci
Merci beaucoup pour votre attention.
Je suis pret a repondre a vos questions.

---

# La demonstration du tableau de bord (a la fin)

> Qui fait quoi : Rachid lance les attaques, Mohammed commente le tableau de bord.
> Duree : environ 5 minutes.

## Avant de commencer (a preparer)
- Ouvrir un terminal dans le dossier du projet.
- Avoir le navigateur pret sur la page du tableau de bord.

## Etape 1 - Lancer le piege
A dire : "On demarre nos trois services piege avec une seule commande."
Commande :
    docker compose up -d --build
A dire : "Voila, six conteneurs demarrent : les trois services, l'analyse et le tableau de bord."

## Etape 2 - Ouvrir le tableau de bord
A dire : "On ouvre le tableau de bord dans le navigateur."
Adresse :
    http://127.0.0.1:8050/
A montrer : la page est encore presque vide. "Pour l'instant, il n'y a pas encore d'attaque."

## Etape 3 - Attaquer le piege
A dire : "Maintenant, Rachid joue le role du pirate. Il lance de vraies attaques sur notre piege."
Commande :
    bash attacks/run_all.sh
A dire : "Ce script utilise Hydra pour essayer plein de mots de passe, et Nikto pour scanner le faux site web."

## Etape 4 - Regarder le tableau de bord en direct
Le tableau se rafraichit tout seul (toutes les 3 secondes). A montrer du doigt :
- Le nombre d'attaques qui monte.
- La carte avec les pays.
- Le camembert des types de pirates (bruteforcer, bot...).
- La liste des derniers evenements.
A dire : "On voit les attaques arriver en temps reel. Le piege reconnait deja un bruteforcer."

## Etape 5 - Prouver que tout marche
A dire : "Pour finir, on lance nos tests automatiques."
Commande :
    python3 attacks/assertions.py
A dire : "Cinq tests sur cinq passent. C'est la preuve que le piege capture, analyse et garde les preuves correctement."

## (Bonus) Montrer l'audit de furtivite
Commandes :
    bash audit/run_audit.sh
    python3 audit/score.py
A dire : "Ce test mesure si notre piege ressemble a un vrai serveur. On est passe de 6 sur 30 a 21 sur 30."

## Si un probleme arrive (plan B)
- Si Docker ne demarre pas : montrer une capture d'ecran du tableau de bord deja rempli.
- Si une commande echoue : rester calme et expliquer ce que la commande devait faire.
- Commandes utiles : `docker compose ps` (voir l'etat), `docker compose down` (tout arreter).

---

# Le contenu du projet (role de chaque dossier)

> A connaitre pour repondre si le jury demande "ou est le code de... ?"

- **honeypots/** : les 3 faux services, le coeur du piege.
    - **honeypots/ssh/** : faux service SSH (connexion a distance) + faux shell Debian.
    - **honeypots/http/** : faux site web (FastAPI) avec des pages pieges (/.env, /wp-login.php...).
    - **honeypots/ftp/** : faux partage de fichiers FTP avec des fichiers appats.
- **common/** (hp_common) : code partage par tous les services. C'est ici qu'on signe les logs (HMAC) et qu'on definit le format commun des evenements.
- **shipper/** : le "facteur". Il prend les logs des services et les envoie a l'analyse.
- **analyzer/** : le cerveau du projet.
    - **api.py** : recoit les evenements (l'API d'ingestion).
    - **classifier.py** + **profiles.json** : decident le type de pirate (les 4 profils).
    - **storage.py** : enregistre tout dans la base de donnees SQLite.
    - **enrichers/** : ajoutent le pays (GeoIP) et la reputation (AbuseIPDB) de l'adresse IP.
    - **exporters.py** : generent les fichiers pour se defendre (Sigma, STIX, iptables).
- **dashboard/** : le tableau de bord web (Dash) qui montre tout en direct.
- **attacks/** : nos scripts pour attaquer notre propre piege (Hydra, Nikto) + les tests (assertions.py).
- **audit/** : les outils pour mesurer la furtivite du piege (nmap, p0f) + le calcul du score sur 30.
- **datasets/** : les listes utilisees pour les attaques (mots de passe, noms d'utilisateurs, chemins, robots).
- **schemas/** : le "contrat" du format des logs (event.schema.json), pour que tous les composants se comprennent.
- **tests/** : les tests automatiques du code (verifient le classifieur et les evenements).
- **docs/** : toute la documentation (ce discours, la presentation, le rapport, l'audit, le RGPD).
- **docker-compose.yml** : le chef d'orchestre. Il demarre les 6 services ensemble.
- **Makefile** : des raccourcis de commandes.
- **pyproject.toml** : la liste des outils Python du projet.
- **README.md** : la presentation rapide du projet.

---

# Questions possibles du jury (reponses simples)

**Q : C'est quoi un honeypot, en une phrase ?**
R : C'est un faux serveur qui sert de piege pour attirer et observer les pirates.

**Q : Pourquoi trois services (SSH, HTTP, FTP) ?**
R : Pour attirer plus de types d'attaques. Chaque service attire des pirates differents.

**Q : Comment vous reconnaissez le type de pirate ?**
R : Avec des regles simples. Par exemple : beaucoup de mots de passe tres vite = un bruteforcer.
Je peux toujours expliquer pourquoi le programme a choisi ce type.

**Q : C'est dangereux ? Le pirate peut-il s'echapper ?**
R : Non. Tout est dans des conteneurs Docker, isoles. Le pirate ne peut pas atteindre une vraie machine.

**Q : Est-ce legal de garder les adresses IP ?**
R : Oui, au titre de la securite (interet legitime). Et je respecte le RGPD : j'anonymise les adresses.

**Q : C'est quoi le score 21 sur 30 ?**
R : C'est mon test de credibilite. Je verifie si on voit que c'est un piege.
Plus le score est haut, plus mon piege ressemble a un vrai serveur.

**Q : Pourquoi pas 30 sur 30 ?**
R : Deux limites que j'assume. Un outil (p0f) voit le systeme de la machine hote, pas mon application.
Et un autre (Honeyscore) marche seulement si le serveur est public sur Internet.

**Q : A quoi servent les exports Sigma et STIX ?**
R : Ce sont des fichiers prets a donner a une equipe de securite pour bloquer les pirates automatiquement.

**Q : Qu'est-ce que vous amelioreriez ?**
R : Rendre le piege encore plus credible, et envoyer des alertes en direct a une equipe de securite.
