SECURE NOTES
============

Une appli web pour stocker et partager des notes et des fichiers, que j'ai
construite pour mettre en pratique le développement sécurisé. L'idée de départ
était simple : prendre l'OWASP Top 10, et essayer de faire une appli où chaque
point est traité concrètement dans le code, avec un test qui prouve que la
protection marche vraiment.

Ce n'est pas une appli révolutionnaire côté fonctionnalités (on crée des notes,
on upload des fichiers, on les partage avec d'autres comptes en lecture ou en
écriture). Tout l'intérêt est dans la façon dont c'est fait.


Stack
-----

Backend : Python 3.13, Flask, SQLAlchemy, PostgreSQL, Redis, Gunicorn
Frontend : React (Vite), servi par Nginx
Le tout tourne dans Docker Compose (4 conteneurs : proxy, backend, db, redis).

Nginx sert le front et relaie /api vers Flask. Le front et l'API sont donc sur
la même origine, ce qui évite d'avoir à ouvrir du CORS et permet de mettre le
cookie de session en SameSite=Strict sans rien casser.


Lancer le projet
----------------

Il faut Docker Desktop (lancé) et Python pour générer les secrets.

    python scripts/generate-secrets.py > .env
    docker compose up --build

Puis aller sur https://localhost:8443. Le certificat est auto-signé, donc le
navigateur râle : il faut accepter l'avertissement.

Attention sous PowerShell : la redirection ">" écrit le fichier en UTF-16 et
Docker n'arrive pas à le lire. Soit utiliser cmd, soit :

    python scripts/generate-secrets.py | Out-File -Encoding ascii .env

Pour lancer les tests :

    docker compose --profile test build tests
    docker compose --profile test run --rm tests

Normalement : 64 passed.


Ce qui est protégé, et comment
------------------------------

Mots de passe
  Hachés avec Argon2id (64 Mo de mémoire par calcul, ce qui rend le cassage
  sur GPU très coûteux). Minimum 12 caractères, pas de mot de passe trop
  courant, pas de mot de passe qui contient l'identifiant. Je n'ai pas mis de
  règles du genre "une majuscule et un symbole", le NIST recommande plutôt la
  longueur.

Sessions
  Je n'utilise pas la session Flask de base (stockée dans le cookie, donc
  impossible à révoquer). Le cookie contient juste un jeton aléatoire de 256
  bits, et la base ne garde que son hash SHA-256. Le cookie est HttpOnly,
  Secure, SameSite=Strict, avec le préfixe __Host-.
  Nouvelle session à chaque connexion (contre la session fixation), expiration
  après 30 min d'inactivité ou 8 h au total, et quand on change de mot de passe
  toutes les autres sessions sont coupées.

Force brute
  Deux niveaux de rate limiting : 5 tentatives par minute par IP, et 10 échecs
  par heure par compte. Le deuxième sert contre le credential stuffing où
  l'attaquant change d'IP à chaque essai. Nginx limite aussi en amont.
  Un détail qui m'a plu : Nginx écrase l'en-tête X-Forwarded-For au lieu de le
  compléter, sinon n'importe qui pourrait se faire passer pour une autre IP et
  contourner la limite.
  Le message d'erreur est le même que le compte existe ou non, et on fait
  quand même un calcul Argon2 pour un compte inexistant, pour que le temps de
  réponse ne trahisse rien.

Injection SQL
  Uniquement l'ORM, aucune requête construite à la main. En plus, toutes les
  entrées sont validées avec Pydantic en mode strict, et un champ en trop dans
  le JSON (genre "is_admin": true) fait rejeter la requête.

XSS
  React échappe tout ce qui est affiché, et il n'y a aucun
  dangerouslySetInnerHTML dans le projet. Derrière, la CSP n'autorise que les
  scripts de la même origine, sans inline ni eval. Même si du HTML passait,
  le navigateur refuserait de l'exécuter.

CSRF
  Plusieurs couches : SameSite=Strict, un jeton CSRF lié à la session et envoyé
  dans un en-tête X-CSRF-Token, une vérification de l'en-tête Origin, et l'API
  n'accepte que du JSON (un formulaire HTML ne peut pas en envoyer).

Contrôle d'accès (IDOR)
  Toutes les routes passent par une seule fonction qui vérifie les droits
  (lecture < écriture < propriétaire). Si on essaie d'accéder à la note de
  quelqu'un d'autre, on reçoit 404 et pas 403, comme ça on ne confirme même pas
  qu'elle existe.

Upload de fichiers
  Le type est détecté sur le contenu réel du fichier avec libmagic (le
  Content-Type envoyé par le navigateur est ignoré). Liste blanche : PDF,
  images, texte. Pas de SVG ni de HTML parce qu'ils peuvent contenir du JS.
  L'extension doit correspondre au contenu. Le fichier est renommé avec un nom
  aléatoire, stocké dans un volume en dehors du dossier web, et au
  téléchargement il est toujours servi en "attachment" avec une CSP sandbox.

Chiffrement au repos
  Les titres et contenus des notes, les noms de fichiers et les fichiers
  eux-mêmes sont chiffrés en AES-256-GCM avant d'arriver en base ou sur le
  disque. Chaque donnée chiffrée est liée à son enregistrement : si on copie le
  contenu chiffré d'une note dans une autre directement en base, le
  déchiffrement échoue. Le format prévoit aussi la rotation de clés.

Configuration
  En-têtes de sécurité (CSP, HSTS, X-Frame-Options, nosniff...), TLS 1.2/1.3
  uniquement, aucune trace d'erreur renvoyée au client, logs de sécurité en
  JSON. Les conteneurs tournent en non-root, sans capabilities Linux, le
  backend en système de fichiers lecture seule, et la base et Redis sont sur un
  réseau interne sans port exposé.


Threat modeling
---------------

J'ai fait l'analyse avec STRIDE sur chaque partie de l'architecture. Les
actifs principaux : le contenu des notes et fichiers, les mots de passe, les
jetons de session et la clé de chiffrement.

Trois frontières de confiance :
  1. Internet -> Nginx : tout ce qui arrive est considéré hostile.
  2. Nginx -> Flask : seuls les en-têtes posés par Nginx sont crus.
  3. Flask -> base / fichiers : je pars du principe qu'un jour quelqu'un
     pourra lire la base ou une sauvegarde, d'où le chiffrement.

Les attaquants envisagés : un anonyme sur Internet, un utilisateur connecté
qui essaie d'accéder aux données des autres, un site tiers qui fait faire des
requêtes au navigateur d'une victime, et quelqu'un qui récupère une copie de
la base.

Ça donne 24 menaces au total, et chacune est reliée à une contre-mesure dans
le code et à un test qui la vérifie.


Tester soi-même
---------------

Les tests automatisés couvrent tout ça (un fichier par famille d'attaques
dans backend/tests). Pour tester à la main, quelques idées :

- Se tromper 6 fois de mot de passe : la 6e tentative renvoie 429.
- Créer deux comptes (une fenêtre normale, une fenêtre privée) et essayer
  d'ouvrir la note de l'un avec l'autre en changeant l'id dans la requête.
- Uploader un fichier HTML renommé en .txt : refusé.
- Regarder le contenu de la base :
    docker compose exec db psql -U securenotes -c "SELECT encode(content_enc, 'hex') FROM notes LIMIT 1;"
  On ne voit que de l'hexadécimal illisible.
- Suivre les logs de sécurité en direct :
    docker compose logs -f backend

Pour aller plus loin : OWASP ZAP pour un scan automatique, Burp Suite pour
rejouer les requêtes à la main, sqlmap sur le formulaire de connexion, et
testssl.sh pour vérifier la config TLS.


Deux trucs que j'ai appris en route
-----------------------------------

Windows Defender a mis un de mes fichiers de test en quarantaine. Il contenait
un vrai webshell PHP qui sert à vérifier que l'upload le refuse, et Defender
l'a pris pour une vraie attaque. Maintenant les charges malveillantes des
tests sont reconstruites au moment de l'exécution, par morceaux, pour
qu'aucune signature n'apparaisse en clair dans le code.

Gunicorn plantait à moitié au démarrage parce qu'il voulait écrire un fichier
dans le dossier perso de l'utilisateur, alors que j'avais mis le conteneur en
lecture seule. Le durcissement faisait son travail. J'ai pointé HOME vers /tmp,
qui est le seul dossier où le conteneur a le droit d'écrire.


Ce qui n'est pas parfait
------------------------

- On peut savoir si un identifiant existe via l'inscription ou le partage.
  C'est difficile à éviter sans rendre l'appli pénible à utiliser, donc c'est
  limité en débit et journalisé.
- Quelqu'un peut bloquer le compte d'un autre pendant une heure en ratant
  exprès 10 connexions. C'est le prix de la protection par compte.
- La clé de chiffrement est dans une variable d'environnement. Ça protège
  contre le vol de la base, pas contre un serveur compromis.
- Le chiffrement n'est pas de bout en bout : le serveur voit les données en
  clair, sinon le partage entre utilisateurs serait beaucoup plus compliqué.

Ce que j'aimerais ajouter : de la double authentification (TOTP ou passkeys),
un vrai gestionnaire de secrets type Vault, un antivirus sur les uploads, et
une CI GitHub Actions qui lance les tests à chaque push.
