# Architecture

PrinceNsamba AI est une application **monolithique volontaire** : un serveur Node.js
qui expose une API JSON, sert l'interface React construite, et possède une base
SQLite locale. Ce choix est délibéré pour un outil autonome : une seule unité de
déploiement, une seule surface d'audit, aucune dépendance externe (ni Redis, ni
Postgres, ni service de files d'attente).

## Vue d'ensemble

```
 Navigateur (React 18, build Vite)
        │  fetch + cookies HttpOnly + en-tête x-csrf-token
        ▼
 Express 4 ── request-context ── security-headers ── helmet ── rate-limit
        │        (id, ip hachée, ua hachée)                (CSP, HSTS…)      (buckets)
        ▼
 middleware/auth.js ──► session (HMAC du jeton) ──► rbac.can(permission)
        │                    deny-by-default : chaque route nomme la permission qu'elle exige
        ▼
 routes/*.js  ── validate.js (schéma strict, types bornés)
        │
        ▼
 services/*   ── logique métier, transactions, journalisation d'audit
        │
        ▼
 repositories/*  ── SQL paramétré, aucun ORM
        │
        ▼
 node:sqlite (fichier + WAL)  ·  volume DATA_DIR (base, sécrètes, fichiers téléversés)
```

## Décisions structurantes

| Décision | Raison | Conséquence |
|---|---|---|
| `node:sqlite` au lieu de `better-sqlite3` | aucune compilation native : l'image Docker n'a ni toolchain ni stage de build C | API synchrone maison (`src/db/index.js`), pragmas WAL/`foreign_keys`/`secure_delete` |
| Argon2id via `@noble/hashes` (pur JS) | `argon2` (binding natif) est optionnel : `password.service.js` le détecte et l'utilise s'il est installé | hachage ≈ 0,9 s par mot de passe avec les paramètres de production en pur JS (coût voulu contre l'attaque hors ligne) ; si le paquet `argon2` est installé, il est détecté et utilisé, le format stocké reste identique (PHC) |
| Jets **jamais** stockés en clair | une fuite de base ne doit pas donner de session réutilisable | seules les empreintes `HMAC-SHA256(SECRET, jeton)` vivent en base ; les cookies transportent le jeton, la comparaison se fait sur l'empreinte |
| Permissions en base, pas dans le code | un rôle se modifie sans déployer | `ADMIN` = les 27 permissions (ligne seedée), `USER` = 6 permissions ; **aucun contournement codé** « si admin alors ok » |
| Audit `append-only` | un journal qui peut être réécrit ne prouve rien | déclencheurs `RAISE(ABORT)` sur UPDATE/DELETE de `audit_logs` ; la purge passe par une procédure hors bande, documentée |
| Fichiers servis uniquement par l'API | le stockage ne doit jamais devenir un vecteur | noms UUID dans `DATA_DIR/uploads/<2 hex>/`, aucune route statique, `Content-Disposition: attachment`, `nosniff`, `CSP: sandbox` |
| Validation serveur systématique | le frontend n'est jamais une autorité | `validateBody`/`validateQuery` sur toute écriture, types bornés, inconnus refusés |

## Modules

```
src/
  config/       env.js (chargement + gardes production + limites), dotenv.js (lecteur .env sans dépendance)
  db/           index.js (DatabaseSync, transactions, normalisation), migrate.js (empreinte SHA-256),
                migrations/001_init.sql … 003_touch_updated_at.sql
  repositories/ accès SQL : users, sessions, files, audit, settings, agents, rbac
  services/     auth, rbac, password, files, documents, zip, url, agents, dashboard, settings,
                audit, rate-limit, bootstrap
  middleware/   request-context, auth, csrf, security-headers, validate, error-handler, upload
  routes/       auth, users (+ routes personnelles montées sur /api/me), rbac, sessions, files,
                documents, urls, agents, admin, health, index.js (createApiRouter)
  utils/        errors (AppError typée), logger (réduction + sinks), crypto, net (SSRF), cookies
  app.js        assemblage Express (crée l'app sans écouter — c'est ce qui rend les tests possibles)
  server.js     exécution : config → migrations → bootstrap → écoute → arrêt gracieux
client/         SPA React (13 pages) : api.js, auth.jsx (contexte), router.js, ui.jsx, styles.css
scripts/        lint.js (portique statique), smoke-test.js, security-audit.js, bootstrap-admin.js,
              video-worker.js (processus de traitement, séparé du serveur web)
tests/          13 fichiers, 271 tests (37 suites), harnais commun (helpers.js)
docker/         entrypoint.sh
```

## Cycle de vie d'une requête authentifiée

1. `request-context` : identifiant de corrélation, IP **hachée** (HMAC), user-agent **haché**, chemin stable.
2. `security-headers` puis `helmet` (CSP, `frame-ancestors 'none'`, HSTS si TLS, `nosniff`).
3. Limiteur de débit : buckets en mémoire, clés `<ipHash>|<route>`, limites `config.limits.*`.
4. `authenticate` : lecture du cookie `ps_session` → empreinte → `sessions` → expiration/réévocation →
   `req.user` (identités + permissions, cache RBAC 15 s).
5. `passwordChangeGate` : si `must_change_password`, seules les routes de la liste `PASSWORD_CHANGE_ALLOW_LIST`
   répondent ; le reste renvoie **403 `PASSWORD_CHANGE_REQUIRED`**.
6. `requirePermission('x:read')` : décision unique, lisible dans la déclaration de la route.
7. `csrf` : le jeton du double-submit doit correspondre **et** à celui stocké sur la ligne de session.
8. `validateBody` : schéma strict, types bornés, clés inconnues refusées.
9. Service → transaction SQL → `audit.record` (ne lève jamais : un échec de journal ne casse pas la requête,
   il est tracé dans le journal applicatif).
10. `error-handler` : les `AppError` rendent statut + code machine + message sûr ; toute autre erreur devient
   un 500 générique **sans pile, sans SQL, sans chemin absolu** (la cause n'est gardée que dans le journal).

## Modèle de données (18 tables)

* **Identité** : `users` (hash PHC + paramètres de hachage + `must_change_password` + verrouillage + `deleted_at`),
  `roles`, `permissions` (31 clés), `user_roles`, `role_permissions`, `settings` (13 clés typées, bornées,
  `is_public`).
* **Sessions** : `sessions` (empreinte de jeton, `csrf_token`, expiration, révocation motivée, empreintes
  IP/UA), `refresh_tokens` (rotation + `family_id` pour la détection de réemploi), `password_reset_tokens`,
  `login_attempts` (fenêtre persistante, indépendante du vidage mémoire).
* **Métier** : `files` (propriétaire, empreinte SHA-256, taille, type détecté, `magic_ok`, compteur de
  téléchargements, `deleted_at`), `document_analyses`, `url_analyses`, `agent_tasks`,
  `video_assets` (rapport de sondage d'un fichier `kind='video'`, `UNIQUE (file_id)`, quarantaine),
  `video_analyses` (une ligne par `kind` et par vidéo, `UNIQUE (video_id, kind)`).
* **Preuve** : `audit_logs` (append-only), `schema_migrations` (empreinte de chaque fichier de migration).

Contraintes actives : clés étrangères (`PRAGMA foreign_keys = ON`), `CHECK` sur les énumérés, `UNIQUE` sur
e-mail/identifiant/nom de rôle/clé de permission/paires, index sur les colonnes de recherche,
`ON DELETE CASCADE` pour les dépendances faibles, `ON DELETE SET NULL` pour l'historique d'audit.

## Extensions prévues

* **Agent Vidéo** : phases A, B et C livrées — déclaration, sondage d'en-têtes en lecture par
  fenêtres, quarantaine, six permissions (`videos:upload|read|read:any|process|stream|manage-jobs`),
  lecture en continu par `Range` (206/416/304, fichier épinglé sur sa taille en base), file
  d'exécution `video_jobs` (claim sous transaction, bail, backoff, idempotence), **vignettes PNG et
  pistes WAV produites par le worker seul** (`src/services/video-media.service.js` +
  `video-ffmpeg.js` : arguments figés, jamais de coquille, délai dur, plafond de sortie, signature
  exigée avant stockage, scratch `0700`) et rattachement des artefacts par `files.parent_file_id`.
  Trois modules partagent une seule politique : `video-source.js` (les octets vérifiés) sert la
  lecture et le traitement, `utils/sanitize.js` sert les deux neutralisations. Le transcodage et la
  transcription restent hors du processus web et **non implémentés** : le worker les refuse par un
  code nommé (`VIDEO_TOOL_UNAVAILABLE`), sans jamais les marquer réussis. Détails et mesures dans
  [`VIDEO-AGENT.md`](VIDEO-AGENT.md).
* **Stockage objet** : `files.service.js` centralise écriture/lecture ; un adaptateur S3 remplacerait le
  système de fichiers sans toucher les routes.
* **Postgres** : les requêtes sont dans les dépôts (`src/repositories`) ; le portage se limite à la syntaxe
  des paramètres et aux `DEFAULT` de date.
