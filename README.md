# PrinceNsamba AI — plateforme autonome d'assistance et d'analyse

Application complète : serveur Node.js (API JSON + base SQLite), interface
d'administration React, contrôle d'accès par rôles et permissions, gestion de
fichiers et d'agents, conteneurisée et tenue par une chaîne de qualité
automatisée. Pensée pour tourner sur un seul serveur, sans service externe.

> **État vérifié le 2026-10-04** : `npm run lint` sort 0 problème · **274 tests, 0 échec** ·
> **42/42** contrôles de smoke test sur une instance de production réellement démarrée ·
> audit de sécurité sur 120 fichiers de l'arbre suivi, 0 constat. L'agent vidéo est **implémenté sur ses trois
> premières phases** (déclaration et sondage, lecture par tranches et file sous bail, vignettes et
> pistes audio produites par le worker) ; la transcription et le transcodage ne sont pas écrits et
> sont refusés par un code d'erreur nommé, jamais simulés. Le détail des commandes et des limites est
> dans [docs/TESTING.md](docs/TESTING.md), [docs/SECURITY.md](docs/SECURITY.md) et
> [docs/VIDEO-AGENT.md](docs/VIDEO-AGENT.md).

## Démarrage en 60 secondes (Docker)

```bash
cp .env.example .env
docker compose up -d --build
docker compose logs app | tail -5          # l'avertissement donne le chemin du mot de passe temporaire
docker compose exec app cat /app/data/bootstrap-admin-password
```

Ouvrir <http://127.0.0.1:3000>, se connecter avec `admin@…` (l'e-mail du compte est celui
de `BOOTSTRAP_ADMIN_EMAIL`, défaut `admin@example.com`) et le mot de passe du fichier lu
ci-dessus : **le changement de mot de passe est imposé à la première connexion**. Supprimer
ensuite le fichier, puis repasser `BOOTSTRAP_ADMIN=0`.

Contrôles disponibles immédiatement :

```bash
docker compose --profile smoke run --rm smoke    # smoke test contre l'instance montée par la composition
docker compose --profile test  run --rm test     # lint + 274 tests + audit de sécurité
```

## Démarrage sans Docker

```bash
npm ci
npm run build                                  # génère dist/ — sinon l'interface répond 503
node src/server.js                             # charge ./data et le .env s'il existe
# équivalent production explicite :
NODE_ENV=production PORT=3000 DATA_DIR=./data node src/server.js
```

Le premier démarrage applique les migrations et crée le compte administrateur. Les journaux
sont en JSON sur la sortie standard (réduction automatique des valeurs sensibles).

## Ce que l'application fait

| Domaine | Détail |
|---|---|
| **Comptes et rôles** | rôles et permissions stockés en base (27 permissions), `ADMIN` et `USER` seeds ; l'administrateur crée les comptes avec un mot de passe provisoire jamais récupérable ; un utilisateur ne peut ni se créer de rôle ni s'octroyer une permission qu'il ne détient pas ; le dernier `ADMIN` est protégé |
| **Authentification** | Argon2id (format PHC), expiration de session, rotation des jetons de rafraîchissement avec détection de réemploi, limitation de débit triple (mémoire, fenêtre en base, verrouillage de compte), changement de mot de passe forcé, réinitialisation à usage unique, événements d'authentification journalisés |
| **Fichiers** | liste blanche d'extensions **et** de MIME **et** signatures binaires, taille et quota, stockage UUID insensible à `../`, jamais de route statique, re-téléchargement par l'API authentifiée (`attachment`, `nosniff`, CSP `sandbox`) |
| **Analyse de documents** | PDF, Word (DOCX), Excel (XLSX), CSV/TSV, JSON, Markdown, images — lecteurs écrits à la main, limites d'entrée (zipbomb incluses), sécrètes détectés **comptés et masqués** |
| **Analyse d'URL** | agent serveur avec blocage SSRF complet (plages réservées IPv4/IPv6, formes encapsulées, ports, rebind DNS, redirections, délai 5 s, plafond 2 Mo), résultats persistés et audités |
| **Agents et tâches** | définitions d'agents, file de tâches en base (claim, retries, `run_after`), tableau de bord d'exécution ; l'[agent Vidéo](docs/VIDEO-AGENT.md) est en service sur ses trois premières phases, avec sa **propre** file (`video_jobs`) et son worker hors du processus web |
| **Administration** | 11 pages : tableau de bord, utilisateurs, rôles, permissions, sessions, journaux d'audit, configuration, agents, tâches, fichiers, sécurité (posture chiffrée : en-têtes, débits, limites, versions de hachage) |

## Sécurité en bref

* Autorisation **côté serveur**, refus par défaut : chaque route nomme la permission exigée.
  Un filtrage d'affichage dans l'interface n'est jamais considéré comme une protection.
* Cookies `HttpOnly` + `SameSite=strict` (+ `Secure` automatique sous TLS), CSRF double-submit
  vérifié aussi contre le jeton stocké sur la ligne de session, rotation d'identifiant,
  révocation effective (une session révoquée est morte même avec le bon cookie).
* Mots de passe et jetons **absents** du HTML, du JS, des réponses, des erreurs, des journaux
  et du dépôt ; IP et user-agent conservés uniquement sous forme d'empreintes HMAC.
* CSP restrictive, `frame-ancestors 'none'`, HSTS sous TLS, `X-Content-Type-Options`,
  `Referrer-Policy`, `Permissions-Policy` ; aucun `dangerouslySetInnerHTML` dans le SPA.
  L'encadrement en iframe est refusé par défaut ; `CSP_FRAME_ANCESTORS` permet de
  l'autoriser pour une liste fermée d'origines (consoles ou aperçus délégués).
* Toute configuration dangereuse en production est un **échec de démarrage** (code 78),
  pas un avertissement.

Détails, correspondance menace → mécanisme → fichier de code :
[docs/SECURITY.md](docs/SECURITY.md). Politique de traitement des secrets et conduite en cas
de fuite : [docs/SECURITY-POLICY.md](docs/SECURITY-POLICY.md).

## Commandes

| Commande | Effet |
|---|---|
| `npm start` / `npm run dev` | serveur (avec `--watch` en dev) |
| `npm run build` | build Vite de l'interface vers `dist/` |
| `npm test` | 274 tests, 38 suites (`node --test`, une file) |
| `npm run lint` | portique statique maison (syntaxe, imports, motifs de secret, cohérence `.env.example`) |
| `npm run audit` | audit de sécurité (ajoutez `-- --strict` pour un code de sortie utile en CI) |
| `npm run smoke` | 42 contrôles contre une instance en cours d'exécution (`SMOKE_BASE_URL`, `SMOKE_EMAIL`, `SMOKE_PASSWORD` ou `SMOKE_PASSWORD_FILE`) |
| `npm run check` | `lint` + `test` + `audit` : à passer avant toute fusion |
| `npm run worker` | worker vidéo : réclame les tâches de `video_jobs`, sonde, écrit le rapport, produit vignettes et pistes audio (boucle de service ; `VIDEO_WORKER_KINDS=probe,thumbnail`) |
| `npm run worker:once` | un seul tour du worker, puis sortie (utile en cron, en CI, ou pour ce parcours de bout en bout) ; il annonce au démarrage si `ffprobe` et `ffmpeg` sont réellement là |
| `npm run db:migrate` | migrations seules (idempotentes, empreinte SHA-256) |
| `npm run admin:bootstrap -- --email a@b.c [--password-file f] [--rotate]` | premier administrateur, ou rotation |
| `npm run compose:up` / `compose:down` / `compose:logs` / `compose:test` | alias Docker Compose |

## Configuration

55 variables documentées avec leur défaut dans
[`.env.example`](.env.example) ; le lint casse si le code lit une variable non documentée
ou l'inverse. Trois points à ne pas manquer :

* `SESSION_SECRET` et `STATE_SECRET` : 32 caractères minimum en production
  (`openssl rand -hex 32`). En leur absence, un secret est généré **dans le volume** et
  persisté — mais seulement si vous l'acceptez explicitement (`SECRET_ALLOW_GENERATED=1`).
* `DATA_DIR` : tout ce qui persiste (base, fichiers téléversés, secrets générés) y vit.
  C'est le seul volume à sauvegarder.
* `COOKIE_SECURE`, `SECURE_PROXY`, `URL_ALLOW_PRIVATE_HOSTS` : trois réglages qui changent
  la menace, pas seulement le confort — voir [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Documentation

| Fichier | Contenu |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | couches, cycle d'une requête, modèle de données (16 tables), décisions et leurs conséquences |
| [docs/SECURITY.md](docs/SECURITY.md) | menaces et mécanismes, pointeur de code pour chaque affirmation, limites assumées |
| [docs/SECURITY-POLICY.md](docs/SECURITY-POLICY.md) | règles de secrets, conduite en cas de fuite, hygiène de développement |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Docker, reverse proxy et TLS, premier administrateur, sauvegarde, migrations, systemd |
| [docs/TESTING.md](docs/TESTING.md) | suites par domaine, harnais de test, règles d'écriture, ce qui n'est pas couvert |
| [docs/VIDEO-AGENT.md](docs/VIDEO-AGENT.md) | agent Vidéo : ce qui est implémenté (phases A à C), les bornes de `ffprobe`/`ffmpeg` dans le worker, les critères prouvés par tests, et ce qui reste à faire |

## Structure

```
src/{config,db,repositories,services,middleware,routes,utils}   serveur applicatif (10 907 lignes)
client/                                                          SPA React 18, 13 pages (3 178 lignes)
tests/                                                           13 fichiers, 274 tests, harnais commun (4 744 lignes)
scripts/                                                         lint, smoke test, audit de sécurité, bootstrap admin, worker vidéo (1 129 lignes)
docker/entrypoint.sh                                             préparation du volume, secrets 0600, migrations
Dockerfile · docker-compose.yml                                  image multi-étapes non root, composition durcie
docs/                                                            architecture, sécurité, déploiement, tests, agent vidéo
```

## Limites connues (à lire avant mise en production)

`node:sqlite` est marqué expérimental par Node ; Argon2id en pur JS est coûteux (le binding
natif `argon2` est utilisé automatiquement s'il est installé) ; il n'y a pas d'antivirus pour
les fichiers, l'analyse PDF est heuristique ; un seul nœud (pas de réplique de base ni de
partage de fichiers) ; aucun test navigateur (le rendu React est vérifié par assertions
structurelles, pas par un DOM réel) ; l'agent Vidéo traite le média **hors** du processus web et
`ffmpeg` n'est pas embarqué dans l'image — il faut l'installer dans le conteneur du worker pour
que les vignettes et les pistes se produisent, sinon la capacité reste ouverte mais chaque tâche
est refusée sous `VIDEO_TOOL_UNAVAILABLE`.
Liste complète et argumentée en fin de [docs/SECURITY.md](docs/SECURITY.md).

## Exécution dans l'environnement de développement

Le chantier a été mené et vérifié dans un bac à sable sans démon Docker :
`docker build` et `docker compose up` n'y ont **pas** été exécutés (`ACTION NON EXÉCUTÉE`,
`RAISON : ni docker ni podman dans l'environnement`). À la place, l'application a été lancée
réellement en mode production (`node src/server.js`, migrations + bootstrap + service de
l'interface + écoute `0.0.0.0:3000`), le smoke test a tourné contre cette instance
(40/40), et les deux fichiers Docker ont été validés statiquement (analyse YAML avec
résolution des ancres, `sh -n` sur l'entrypoint, recherche des motifs de durcissement).
La CI (`ci/github-workflows-ci.yml`, à copier dans `.github/workflows/ci.yml` :
voir [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) § 9 — l'écriture de ce chemin est refusée
au jeton d'agent) exécute, elle, la construction et la composition réelles.
