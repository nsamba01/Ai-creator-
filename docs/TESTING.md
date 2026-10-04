# Tests et chaîne de qualité

## Commandes

```bash
npm test                      # 274 tests, 38 suites, une seule file (--test-concurrency=1)
npm run test:one -- tests/rbac.test.js   # un seul fichier de suite
npm run lint                  # portique statique maison (aucune dépendance externe)
npm run audit                 # audit de sécurité (secrets, index Git, config, Docker, npm audit)
npm run build                 # build Vite de l'interface (nécessaire pour que / serve la SPA)
npm run check                 # lint + tests + audit : c'est LE contrôle à passer avant de committer
npm run smoke                 # 42 contrôles contre une instance réellement en cours d'exécution
```

`npm run check` est ce que la CI exécute (workflow fourni sous `ci/github-workflows-ci.yml`, à copier dans
`.github/workflows/ci.yml` — voir docs/DEPLOYMENT.md § 9). Résultat mesuré le 2026-10-04 dans cet
environnement : lint `Aucun problème détecté` (sortie 0, 7 dérogations `lint-allow` comptées),
**274 tests, 0 échec** (38 suites), audit de sécurité : **121 fichiers passés en revue, 0 constat**
(le compte suit l'arbre suivi, `.env` local compté en plus), et smoke contre une instance de
production locale : **40/40** sur une instance fraîche aux réglages durcis — le nombre de contrôles
Applicables varie avec l'état de l'instance (42 quand les capacités vidéo sont éteintes).

Un second parcours, écrit pour la vérification de mise en service (serveur vivant, base fraîche,
`VIDEO_WORKER_KINDS=probe,thumbnail`, `FFMPEG_PATH` désignant un binaire absent) : **37 contrôles sur
37** — déduplication par empreinte (200 plutôt qu'un second objet), refus à la matière (415) d'un
PNG renommé `.mp4`, refus nommé (409) avant l'allumage du réglage, sondage réel depuis les en-têtes
ISO BMFF (`ready`, `source=header`, 1280x720 relevés sur un fichier de démonstration), enregistrement
idempotent, `Range` en 206 à l'octet près, quarantaine coupant tout octet servi, temporisation de la
file opposable (réclamer trop tôt ne consomme pas de tentative), échec nommé `VIDEO_TOOL_UNAVAILABLE`
puis terminal à `video.max_attempts = 1`, et aucun artefact produit par les passes échouées.

## Ce que couvre chaque suite

| Fichier | Contenu (résumé) |
|---|---|
| `tests/db.test.js` | migrations (ordre, idempotence, empreinte SHA-256 et **détection de falsification**), pragmas, contraintes `CHECK`/`UNIQUE`, transactions, `foreign_keys`, `updated_at` entretenu par le déclencheur de `003`, colonnes réelles |
| `tests/password.test.js` | aller-retour PHC, sel unique, vérification à temps constant, `needsRehash`, politique de complexité, dictionnaire et variantes « leet », refus du nom d'utilisateur, génération de mots de passe provisoires sans caractère ambigu |
| `tests/auth.test.js` | connexion, 401 générique identique pour mot de passe faux/inconnu/compte désactivé, changement forcé, rotation de session, expiration, révocation, refresh : rotation, détection de réemploi et révocation de la famille, réinitialisation à usage unique, journalisation des événements d'authentification |
| `tests/rbac.test.js` | 27 permissions seeds, matrice ADMIN/USER, refus par défaut route par route, anti-escalade (donner une permission qu'on ne détient pas), dernier administrateur protégé, cache invalidé, portée des données d'un `USER` |
| `tests/admin.test.js` | tableau de bord agrégé, édition de configuration typée et bornée, file de tâches d'agents, révocation de toutes les sessions, posture de sécurité exposée |
| `tests/audit.test.js` | immuabilité (`UPDATE`/`DELETE` refusés par déclencheurs), champs présents, IP/UA sous forme d'empreinte, pagination/filtres, aucune valeur sensible écrite |
| `tests/files.test.js` | téléversement (extension + MIME + signature binaire), refus des vecteurs d'exécution, taille et quota, nommage UUID et résistance à `../`, dé-duplication par propriétaire, re-téléchargement, suppression logique + unlink, IDOR (lire/effacer le fichier d'autrui), compteur de téléchargements |
| `tests/documents.test.js` | DOCX/XLSX (limites ZIP : taille décompressée, ratio, nombre d'entrées), CSV/TSV, JSON, Markdown, PDF heuristique, images (dimensions), masquage des sécrètes détectées |
| `tests/url.test.js` | classification SSRF (IPv4/IPv6, plages réservées, `::ffff:127.0.0.1`, `2002::`), ports, redirections, délai, plafond d'octets, ré-épreuve de l'adresse résolue, aucune trace d'identifiants dans l'URL journalisée |
| `tests/videos.test.js` | 28 sous-tests de l'agent vidéo (phase A) : commutateur en base, signature de conteneur, plafond de taille appliqué **pendant** le corps, refus d'un `.png` renommé, durée et dimensions hors bornes → quarantaine, `meta_json` borné, portée propriétaire sur le rapport, quarantaine/levée, `probe_source` fidèle à ce qui a été **lu** |
| `tests/video-stream.test.js` | 23 sous-tests de la phase B : découpage `Range` en unitaire (plage unique, queue, `bytes=1-0`, multi-plages), comparaison octet par octet contre `fs`, 416 sans corps, 304, HEAD, les gardes de la route dont `VIDEO_SIZE_MISMATCH` provoqué en modifiant le fichier sur disque, claim exclusif par un seul worker, isolement par kinds, bail expiré repris et écriture refusée au worker décroché, backoff mesuré sur `run_after`, échec à `max_attempts`, message sans chemin, idempotence `UNIQUE(video_id, kind)`, purge journalisée, artefacts rattachés et emportés par la suppression de la source, `CHECK` de `video_jobs`, permissions |
| `tests/video-tools.test.js` | 23 sous-tests de la phase C : argv sans aucun mot du client et borné des deux côtés, scratch `0700` et contention du nom, exécution **réelle** d'un shim POSIX (succès, sortie trop volumineuse jetée du disque, SIGKILL au délai mesuré, code non nul traduit sans chemin, sortie vide ou non-PNG refusée, jamais de coquille), les six portes du service (capacité, portée, prêt, taille épinglée, binaire, signature), rattachement et relecture en ligne de l'artefact, `audio/wav` sous la même politique de stockage que les téléversements, refus de capacité journalisé, `input` de tâche re-borne, 404 non bavard |
| `tests/security.test.js` | en-têtes et CSP, cookies (HttpOnly/`secure`/`SameSite`), CSRF double-submit + jeton de session, 401/403/404 normalisés sans fuite, échappement de rendu (charge XSS stockée puis rendue inerte), `redact()` au sink, charge utile JSON limite, refus des clés inconnues, **lecteur `.env`** (priorité à l'environnement, symlink/hors-racine refusés, aucune valeur journalisée) |

## Parcours de bout en bout avec le worker

Les suites ci-dessus tiennent en un seul processus. La file d'exécution ne se prouve qu'avec
**deux** : le serveur qui accepte la déclaration, et `scripts/video-worker.js` qui la traite.
Rejouable ainsi :

```bash
cp .env.example .env                 # puis renseigner DATA_DIR, SESSION_SECRET, STATE_SECRET
node src/server.js &                 # API + SPA sur :3000
node scripts/bootstrap-admin.js --email admin@local.test --password-file data/bootstrap-admin-password
FFMPEG_PATH=/chemin/vers/ffmpeg npm run worker:once   # un tour de file, puis sortie (le mode service : `npm run worker`)
```

Sans `ffmpeg` sur la machine — le cas de cet environnement de développement — le worker dit la
vérité et le prouve : il annonce `ffmpeg absent` au démarrage, accepte la tâche, puis la refuse
`VIDEO_TOOL_UNAVAILABLE` (503). Les tests, eux, désignent un **shim POSIX** (`/bin/sh` écrit par la
suite dans un dossier temporaire) par `FFMPEG_PATH` : le processus est réellement lancé, et se
comporte parfois mal (sortie énorme, fausse signature, blocage) — c'est l'enveloppe que nous
contrôlons qui est vérifiée, pas le décodeur.

Ce qu'il faut y voir, et qui y a été vu le 2026-10-02 (21/21 contrôles) : avec
`video.async_probe` à `true`, la déclaration répond `201` avec `queued: true` et un rapport
`pending` (aucune durée inventée) ; `GET /api/videos/:id/stream` répond `409 VIDEO_NOT_READY` ;
le tour de worker passe la tâche en `succeeded` et **remplit le rapport** ; la lecture répond
alors `200`, et `Range: bytes=100000-100999` rend `206` avec exactement ces mille octets ; une
tâche `thumbnail` reste `queued` devant un worker `VIDEO_WORKER_KINDS=probe`, puis est refusée
`VIDEO_TOOL_UNAVAILABLE` par un worker `VIDEO_WORKER_KINDS=thumbnail`.

Le run de la phase C (19/19, 2026-10-02, même montage : serveur vivant + `worker:once` vivant +
shim désigné par `FFMPEG_PATH`) ajoute : `video.tools_enabled` fermé → tâche acceptée `202` puis
refusée `VIDEO_TOOLS_DISABLED` **et reprogrammée** (`attempts: 1`, `run_after` dans le futur, échec
terminal à `video.max_attempts = 1`) ; capacité ouverte → vignette produite avec `width`, `atMs` et
`maxBytes` réellement appliqués, relue en `image/png` par la route de contenu ; piste `wav` relue en
`audio/wav` avec `magic_ok` vrai ; sortie non-image et sortie au-dessus du plafond jetées sans ligne
`files` orpheline ; outil bloqué tué au délai (2,5 s mesurés) sans emporter le serveur ; artefact
invisible au compte voisin (403) et à l'anonyme (401) ; refus et créations dans `audit_logs` ; et
aucun chemin absolu dans les 19 000 octets de réponses capturées ni dans le journal du serveur.

## Harnais (`tests/helpers.js`)

`boot({ adminPassword, userPassword, extra })` lève une instance **réelle** de
l'application pour chaque test : répertoire `DATA_DIR` temporaire, port `0` (le serveur
choisit), `NODE_ENV=test`, `COOKIE_SECURE=0`, `SameSite=lax`, paramètres Argon2 abaissés
pour la vitesse (le format et les chemins de code restent ceux de la production), limite de
corps relevée pour les tests de fichiers. Il renvoie un client `fetch` avec **pot de
cookies** et **jeton CSRF** gérés automatiquement, des builders de documents (zip, docx,
xlsx, pdf, PNG) fabriqués à la volée dans le test, et `close()` qui referme base et
serveur.

Règles d'écriture, issues des faux positifs rencontrés :

1. **jamais de réseau** dans un test : toute URL sortante est simulée ou attendue refusée ;
2. ne pas dépendre d'une temporisation (les tests de verrouillage comptent des requêtes,
   pas des secondes) ;
3. comparer une charge XSS sur `JSON.stringify(...)`, jamais sur l'objet (l'échappement est
   une propriété du rendu) ;
4. `assert.ok(cond, msg)` et non `assert.equal(cond, true, msg)` (le second avale le
   message) ;
5. les assertions textuelles doivent contenir les **mots français réellement produits** par
   le serveur ;
6. une fixture ne doit jamais contenir le nom d'utilisateur dans son mot de passe
   (politique serveur), ni un secret qui serait réduit par `redact()` si elle est
   journalisée ;
7. un compte en `must_change_password` est bloqué hors liste blanche : les fixtures
   d'API le changent d'abord.

## Portique de lint (`scripts/lint.js`)

`node --check` sur les 61 fichiers JS (les `.jsx` sont exclus : le parseur Node ne connaît
pas le JSX), vérification que chaque import relatif résout, motifs de secrets dans les
sources, primitives dangereuses (`child_process`, `eval`, `Function`), `console.*` interdit
dans `src/`, interpolation SQL, garde anti-`DROP` dans les migrations, présence obligatoire
de `.gitignore` et `.dockerignore`, **cohérence bidirectionnelle** `.env.example` ↔
`process.env.*` lus par le code. `tests/` et `docs/` (+ `README.md`) sont traités comme des fixtures : la documentation
**nomme** les primitives dangereuses et les tests manipulent des identifiants fictifs ;
on n'y recherche donc que les fuites à haute confiance (clés AWS, clés privées, jetons
SaaS). Le code applicatif et les scripts restent stricts, avec une dérogation possible
par commentaire `// lint-allow: <motif>` sur les trois lignes qui précèdent — chaque
dérogation est **comptée et affichée** dans le résumé du lint (trois aujourd'hui, toutes
dans `scripts/security-audit.js` pour `git ls-files` et `npm audit` en lecture seule).
Sortie non nulle = CI rouge.

## Migrations

`src/db/migrations/*.sql` sont appliquées dans l'ordre numérique au démarrage et par
`npm run db:migrate`. Chaque fichier est horodaté par empreinte SHA-256 dans
`schema_migrations` : modifier une migration déjà appliquée fait échouer le démarrage.
**Toute correction passe donc par un nouveau fichier numéroté** (exemple en place :
`003_touch_updated_at.sql` ajoute l'entretien de `updated_at`, sans retoucher `001`).
Un test d'échec de vérification d'empreinte protège cette règle.

## Ce qui n'est pas couvert

* Pas de test navigateur (Playwright) : la chaîne de rendu est vérifiée par des assertions
  structurelles côté serveur + absence de `dangerouslySetInnerHTML`.
* Pas de test de charge ni de test de reprise après sinistre.
* Pas de test d'intrusion : `smoke-test.js` vérifie la posture, pas l'exploitabilité.
