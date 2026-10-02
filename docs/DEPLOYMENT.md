# Déploiement

## 1. Avec Docker Compose (recommandé)

Deux fichiers sont fournis à la racine : `Dockerfile` (multi-étapes, image finale sans
toolchain) et `docker-compose.yml`.

```bash
cp .env.example .env
# obligatoires : SECRET_ALLOW_GENERATED=0, et deux secrets longs
printf 'SESSION_SECRET=%s\nSTATE_SECRET=%s\n' "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" >> .env
# premier démarrage uniquement : laisser BOOTSTRAP_ADMIN=1, l'administrateur se connecte
# avec le mot de passe écrit dans le volume, puis le change immédiatement
docker compose up -d --build
docker compose logs -f app
docker compose --profile smoke run --rm smoke     # 40 contrôles contre l'instance réelle
docker compose port app 3000                       # vérifie l'adresse publiée
docker compose --profile test run --rm test       # lint + 248 tests + audit de sécurité
```

Arrêt, nettoyage, mise à jour :

```bash
docker compose down                  # le volume princesamba_data est conservé
docker compose build && docker compose up -d
docker volume ls | grep princesamba_data
```

### Ce que fait la composition

| Service | Rôle |
|---|---|
| `volume-init` | one-shot **root** avec `CHOWN`/`FOWNER` uniquement : rend `princesamba_data` lisible/écrivable par l'UID 10001, puis s'arrête ; `app` l'attend via `service_completed_successfully` |
| `app` | l'application, image cible `production`, système de fichiers **en lecture seule**, volume monté sur `/app/data`, ports publiés `${APP_BIND:-127.0.0.1}:${APP_PORT:-3000}` (boucle locale par défaut) |
| `smoke` | profil `smoke`, attend `service_healthy` puis lance `node scripts/smoke-test.js` |
| `test` | profil `test`, image cible `test` (dépendances de développement incluses), lance lint + tests + audit |

Durcissement appliqué aux conteneurs applicatifs : `cap_drop: [ALL]`,
`security_opt: [no-new-privileges:true]`, `read_only: true`, `tmpfs /tmp` en `noexec`,
`restart: unless-stopped`, rotation des logs (`json-file`, 4 Mo × 4).

### Entrypoint

`docker/entrypoint.sh` (POSIX `sh`, `set -eu`, `umask 077`) prépare un volume monté
**vierge** avant l'exécution : répertoires de données, secrets `SESSION_SECRET` /
`STATE_SECRET` générés et écrits en `0600` dans `DATA_DIR/.secret-*` **uniquement si
absents**, migrations, puis `exec "$@"`. Les secrets existants ne sont jamais
écrasés : ils sont relus au démarrage suivant (`src/config/env.js`, source `volume`).

Les mêmes commandes ont des alias npm : `npm run compose:up`, `compose:down`,
`compose:logs`, `compose:test`.

## 2. Configuration

55 variables sont documentées dans `.env.example` (dont huit lues uniquement par Docker Compose
ou par les outils : `APP_BIND`, `APP_PORT`, `SMOKE_*`) ; `node scripts/lint.js` vérifie que
**toute variable lue par le code est documentée et réciproquement** — un nouveau `process.env.X`
sans ligne dans `.env.example` casse le lint.

Les plus importantes :

| Variable | Défaut | Effet si mal réglée |
|---|---|---|
| `SESSION_SECRET`, `STATE_SECRET` | — | refus du démarrage en production si absent, < 32 caractères ou placeholder connu |
| `SECRET_ALLOW_GENERATED` | `0` | seul opt-in qui autorise une génération automatique en production |
| `COOKIE_SECURE` / `COOKIE_SAMESITE` | `auto` / `strict` | `none` sans `secure` = refus |
| `CSRF_PROTECTION` | `1` | `0` en production = refus |
| `SECURE_PROXY` | `0` | à activer **uniquement** derrière un reverse proxy de confiance, sinon l'en-tête `X-Forwarded-For` permet de tromper le débitmètre |
| `URL_ALLOW_PRIVATE_HOSTS` | `0` | `1` transforme l'application en proxy interne : journalisé comme avertissement |
| `MAX_UPLOAD_MB` / `MAX_QUOTA_MB` | `10` / `500` | tailles refusées au-delà, quota par utilisateur |
| `LOGIN_MAX_ATTEMPTS` / `ACCOUNT_LOCK_MINUTES` | `5` / `30` | verrouillage de compte, persistant en base |
| `DATA_DIR` / `DB_PATH` / `UPLOAD_DIR` | `./data` | doit être un volume montable, seul chemin persistant |
| `BOOTSTRAP_ADMIN` | `1` | à remettre à `0` après la création du premier administrateur |
| `DISABLE_AUTH_FOR_TESTS` | `0` | ignoré silencieusement hors tests unitaires ; présent en production = refus |

## 3. Reverse proxy et TLS

L'application ne termine **pas** le TLS. Exemple Caddy :

```
app.example.com {
  reverse_proxy 127.0.0.1:3000
}
```

Puis dans `.env` : `PUBLIC_BASE_URL=https://app.example.com`, `COOKIE_SECURE=1`,
`COOKIE_PREFIX=__Host-`, `SECURE_PROXY=1`, `CORS_ALLOWED_ORIGINS=https://app.example.com`.
Avec un préfixe `__Host-`, le navigateur refuse que le cookie soit posé sans `Secure`,
sans `Path=/` et sans domaine : le réglage est auto-contrôlant.

Nginx : `proxy_set_header X-Forwarded-Proto $scheme;` et `X-Forwarded-For $proxy_add_x_forwarded_for;`,
`client_max_body_size` **inférieur ou égal** à `MAX_UPLOAD_MB` (sinon c'est Nginx qui renvoie
une page d'erreur au lieu de l'API), `proxy_read_timeout 60s`.

## 4. Premier administrateur

```bash
docker compose exec app node scripts/bootstrap-admin.js --email admin@exemple.fr --username admin
```

Trois niveaux existent, dans cet ordre de priorité :

1. `BOOTSTRAP_ADMIN_PASSWORD` dans l'environnement — réservé à un déploiement piloté
   (secrets manager), ne pas mettre de mot de passe dans un fichier versionné ;
2. `--password-file <chemin>` — lecture d'un fichier, jamais de l'argument de ligne de
   commande (il serait visible dans `ps`) ;
3. sans les deux, un mot de passe **provisoire** est généré, écrit en `0600` dans
   `DATA_DIR/bootstrap-admin-password`, et le compte est marqué `must_change_password`.

Cas limites traités explicitement (`src/services/bootstrap.service.js`) : compte déjà
présent (réinstallation, pas d'écrasement du mot de passe), empreinte différente (réservé,
refus), **dernier administrateur verrouillé** (refus), mot de passe non conforme à la
politique (refus et aucun compte créé), mot de passe par défaut (refus et le compte est
marqué pour changement immédiat).

## 5. Sauvegarde et restauration

```bash
# sauvegarde cohérente (checkpoint WAL avant copie) ; note : aucun binaire sqlite3 n'est requis
docker compose exec app node -e "const {DatabaseSync}=require('node:sqlite');const db=new DatabaseSync(process.env.DB_PATH);db.exec('PRAGMA wal_checkpoint(TRUNCATE);');db.close()"
docker run --rm -v princesamba_data:/data -v "$PWD:/backup" alpine \
  tar czf /backup/psai-$(date -u +%Y%m%dT%H%M%SZ).tar.gz -C /data .
```

La restauration est le `tar xzf` inverse dans le volume, puis `docker compose up -d`.
Le fichier de secrets `.secret-*` **doit** être sauvegardé avec la base : sans la clé
HMAC d'origine, toutes les sessions, jetons de rafraîchissement et empreintes d'adresses
deviennent illisibles (les utilisateurs sont déconnectés, aucun compte n'est perdu).
Politique recommandée : quotidienne, 30 jours, hors du serveur, chiffrée au repos.

## 6. Sans Docker

```bash
npm ci
npm run build                  # génère dist/ (sinon l'API répond mais pas l'interface)
NODE_ENV=production PORT=3000 DATA_DIR=/var/lib/princesamba node src/server.js
```

Unité systemd : `DynamicUser=yes`, `StateDirectory=princesamba`, `ProtectSystem=strict`,
`ReadWritePaths=/var/lib/princesamba`, `PrivateTmp=yes`, `NoNewPrivileges=yes`,
`CapabilityBoundingSet=`vide, `EnvironmentFile=/etc/princesamba/env`. L'application ne
doit écrire que dans `DATA_DIR`.

## 7. Mises à jour et retours arrière

* Les migrations sont montantes et horodatées avec une empreinte SHA-256 ; une migration
  déjà appliquée est **refusée** si son contenu change (`docs/TESTING.md` § migrations).
  Une correction se fait donc dans un nouveau fichier numéroté, jamais en retouchant un
  fichier appliqué.
* Avant une mise à jour : sauvegarder le volume (point 5). L'image est taguée
  `princesamba-ai:local` : avant de reconstruire, `docker tag princesamba-ai:local
  princesamba-ai:avant`, puis en cas d'échec `docker tag princesamba-ai:avant
  princesamba-ai:local && docker compose up -d --no-build` (si la base a migré, restaurer
  aussi le volume : les migrations ne sont pas descendantes).
* `docker compose exec app node src/db/migrate.js` est idempotent et sert de vérification.

## 8. Contrôle de sécurité automatisé

```bash
npm run audit            # secrets, index Git, permissions, gardes de config, Docker, npm audit
npm run audit -- --strict   # exit code non nul dès qu'un constat reste ouvert
```

Résultats mesurés le 2026-10-02 dans cet environnement : `ACTION NON EXÉCUTÉE` pour la
construction de l'image (ni `docker` ni `podman` dans le bac à sable) — voir le rapport de
session ; la validation statique des deux fichiers (analyse YAML, `sh -n`, recherche des
motifs) a été exécutée à la place.

## 9. Chaîne d'intégration continue

> **Le fichier de workflow n'est pas sous `.github/workflows/`.** Il est fourni sous
> `ci/github-workflows-ci.yml` : le jeton de l'agent (GitHub App) n'a pas la permission
> `workflows`, et GitHub refuse toute écriture créant ou modifiant un fichier sous
> `.github/workflows/` sans cette permission. Pour l'activer :
>
>     mkdir -p .github/workflows
>     cp ci/github-workflows-ci.yml .github/workflows/ci.yml
>     git add .github/workflows/ci.yml && git commit -m "CI" && git push
>
> (ou accorder `Workflows: write` à l'application GitHub, puis relancer la commande).
> Le contenu est vérifié localement : les mêmes étapes (`lint`, `test`, `build`, `smoke`,
> `audit -- --strict`) passent dans cet environnement.

Trois emplois : `quality` (lint, 248 tests, build Vite, instance de production réellement
démarrée puis smoke test, audit `--strict` avec artefact JSON de 14 jours), `docker`
(`docker compose config -q`, construction des deux cibles `production` et `test`, chaîne de
qualité exécutée dans le conteneur de test, `up -d --build` puis smoke), `docs` (les
commandes citées dans la documentation existent réellement, les fichiers de déploiement et
les six fichiers de documentation sont présents, `sh -n` sur l'entrypoint).

Aucun secret n'y est écrit : les valeurs sont générées par le job (`openssl rand -hex 32`),
le mot de passe administrateur de test transite par un fichier temporaire `0600` passé à
`--password-file` puis supprimé, et le `.env` du job Docker est créé de zéro (pas de copie
de `.env.example` : Compose applique la dernière valeur rencontrée, un doublon rendrait le
résultat ambigu).
