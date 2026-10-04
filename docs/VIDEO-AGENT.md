# Agent Vidéo — architecture

> **Statut : phases A, B et C implémentées et testées ; phase D en conception.**
> La phase C ouvre l'exécution d'un outil média réel (`ffmpeg`) **dans le worker seul**, sous
> commutateur. Aucun binaire de ce genre n'est installé dans l'environnement de développement :
> la chaîne a été prouvée avec un **shim POSIX** (`/bin/sh`) qui joue le rôle de l'outil, donc ce
> qui est vérifié est l'enveloppe — bornes, délais, plafonds, signatures, portées, journal — pas
> la qualité du décodeur. C'est écrit ici, pas dans une note de bas de page.
> Ce document décrit d'abord ce qui est réellement dans le code (avec les chemins de
> fichiers), puis ce qui reste à faire. Toute ligne qui n'est pas écrite est marquée
> « prévu » ; rien n'est présenté comme fonctionnel sans test correspondant. Les mesures
> citées (nombres de tests, de permissions, de réglages, tailles d'octets servies) ont été
> obtenues en exécutant les commandes dans ce dépôt, pas estimées.

## Objectif

Permettre à un utilisateur autorisé de confier une vidéo (téléversée, plus tard adressée
par URL) à un agent qui produit : un rapport technique (conteneur, pistes, codec, durée,
résolution, débit, fréquence d'images), puis — après les phases suivantes — une extraction
audio et une transcription, une planche de vignettes, une détection de parties
silencieuses/noires et une modération légère — **sans jamais exécuter le média ni ouvrir de
chemin arbitraire**.

## Ce que la phase A fait réellement

1. **Ingestion par le pipeline de fichiers existant.** Aucun chemin de stockage alternatif :
   le média entre par `POST /api/files` (ou `POST /api/videos/upload`, qui appelle
   `files.store` après un pré-filtre sur l'extension) et reçoît ainsi la liste blanche
   d'extensions, le contrôle des octets de tête (`MAGIC`), la taille maximale, le nommage
   UUID, le quota et le `owner_id`. `video/*` a rejoint `KIND_BY_EXT`, `MIME_FAMILIES` et
   `MAGIC` dans `src/services/files.service.js` ; les extensions interdites
   (`FORBIDDEN_EXTENSIONS`) restent exclues.
2. **Déclaration d'un activer vidéo.** `video_assets` est une table fille de `files`
   (`UNIQUE (file_id)`), donc une vidéo = un fichier, avec son propre état de traitement.
   Redéclarer le même fichier renvoie l'état courant sans insérer de ligne ni de seconde
   copie d'octets.
3. **Sondage en lecture partielle.** `src/services/video-probe.js` analyse **la tête et la
   queue du fichier uniquement** (fenêtre `VIDEO_PROBE_WINDOW_KIB`, 512 Kio par défaut),
   jamais le fichier entier : MP4/MOV/M4V (boîtes `ftyp`/`moov`/`mvhd`/`tkhd`/`mdhd`/`stsd`/
   `stts`, y compris `moov` écrit en fin de fichier), Matroska/WebM (EBML, `Info`, `Tracks`,
   `Cluster`), AVI (`RIFF/AVI `, `hdrl/avih`, `strl/strh/strf`, `idx1`). Un conteneur
   inconnu produit `VIDEO_UNSUPPORTED_CONTAINER`, pas une exception.
4. **ffprobe optionnel, doublement gardé.** activé par `VIDEO_USE_FFPROBE=1` **et** le réglage
   base `video.use_ffprobe` ; le binaire est validé par `safeBinaryPath()` (chemin absolu ou
   nom simple, `[A-Za-z0-9._/-]` seulement, refus de `..`, existence + bit d'exécution),
   exécuté **sans shell**, avec une table d'arguments figée, un `PATH` restreint, un délai
   (`VIDEO_PROBE_TIMEOUT_MS`) et un plafond de sortie de 1 Mio. L'empreinte du fichier est
   calculée côté serveur et n'atteint jamais la ligne de commande. En cas d'échec, on garde
   le rapport d'en-têtes et on le note — aucune fausse valeur n'est inventée.
5. **Quarantaine plutôt que rendu.** Durée hors bornes, géométrie incohérente, fichier
   tronqué ou `moov` introuvable → l'actif passe en `quarantaine` avec un `error_code` ; le
   rapport est quand même consultable, et la levée de quarantaine demande `videos:process`. Un
   fichier incohérent n'est jamais « lu » ni monté. Le refus **conserve les faits déjà lus**
   (conteneur, dimensions, codec, lecteur) : un rapport de quarantaine muet ne laisserait à
   l'administrateur aucune matière pour trancher. Inversement, lever une quarantaine sur une
   vidéo jamais sondée ne la déclare pas `ready` : elle repasse en `pending` et doit être
   sondée.
6. **Portée et journalisation.** Les requêtes sont filtrées par propriétaire sauf permission
   `videos:read:any` ; les événements `video.registered`, `video.probed`, `video.quarantined` et
   `video.released` sont écrits dans `audit_logs` (catégorie `agents`) avec des détails réduits :
   identifiants, conteneur, état, taille — jamais l’empreinte complète, jamais de chemin disque
   ni de nom de stockage. Vérifié sur la base de production : `SELECT count(*) FROM audit_logs
   WHERE detail_json LIKE '%/home/%' OR detail_json LIKE '%data/uploads%'` → 0.
7. **Interface.** `client/pages/Videos.jsx` (entrée « Agent vidéo », gardée par
   `videos:read`) : compteurs de posture, téléversement, déclaration par identifiant, table
   des rapports, fiche de détail avec pistes et notes, boutons de re-sondage et de
   quarantaine — chaque action étant re-décidée par le serveur. Phase B : la fiche monte un
   `<video src="/api/videos/:id/stream">` **seulement** si le serveur déclare la capacité ouverte
   (`stats.streaming`) et le rapport prêt, un bordereau des tâches déléguées à la vidéo (état,
   tentatives, prochain réveil, erreur nommée) avec annuler/reprendre, et les kinds lourds ne sont
   proposés qu'au compte qui a `videos:process` — l'affichage suit la permission, mais c'est le
   serveur qui la vérifie à chaque appel.

## Ce que la phase A ne fait pas (à ne pas vendre)

* le **lecteur et le flux** (`GET /api/videos/:id/stream`, `Range`, 206/416/304) ne sont plus
  à écrire : voir la section « Phase B » ci-dessous. Ils restent fermés tant que le réglage
  `video.stream_enabled` est faux, ce qui est l'état par défaut ;
* **aucun transcodage ni transcription** : la phase C ajoute la vignette et la piste WAV, pas un
  réencodeur ni un modèle ASR — `ffmpeg` n'est appelé que pour ces deux gestes, et `transcribe`
  reste un refus nommé (`VIDEO_TOOL_UNAVAILABLE`) tant qu'aucun modèle local n'est branché ;
* **aucun collecte par URL** : `POST /api/videos/from-url` répond `501 NOT_IMPLEMENTED` —
  l'agent de collecte refuse délibérément de télécharger un média tant que le bac à sable du
  worker n'existe pas ;
* le **plan d'exécution asynchrone** est la table `video_jobs` (phase B), pas `agent_tasks` :
  les tâches média ont besoin d'un bail, d'un preneur unique et d'un compteur de tentatives,
  trois choses qu'aucune colonne de `agent_tasks` ne représentait. Le synchrone reste le
  comportement par défaut (`video.async_probe = false`) ; l'administrateur choisit la voie.

## Modèle de données (migration `004_video_agent.sql`, appliquée)

| Table | Colonnes | Notes |
|---|---|---|
| `video_assets` | `id`, `file_id` (UNIQUE, FK → `files` `ON DELETE CASCADE`), `owner_id`, `task_id`, `container`, `brand`, `codec`, `duration_ms`, `width`, `height`, `fps`, `bitrate_bps`, `track_count`, `index_entries`, `fragmented`, `truncated`, `parser`, `probe_source`, `status`, `error_code`, `meta_json`, `probed_at`, `created_at`, `updated_at`, `deleted_at` | `status ∈ (pending, probing, ready, failed, quarantined)` ; `probe_source ∈ (none, header, ffprobe, header+ffprobe)` ; `CHECK` de bornes sur durée, dimensions, débit, pistes ; `length(meta_json) ≤ 16000` ; `updated_at` entretenu par un déclencheur |
| `video_analyses` | `id`, `video_id`, `kind`, `status`, `model`, `result_json`, `error_code`, `duration_ms`, `created_at`, `finished_at` | `kind ∈ (probe, transcode, transcribe, thumbnail, moderation)` ; **`UNIQUE (video_id, kind)`** : rejouer une analyse met à jour la ligne, n'ajoute rien |
| `files` (existante) | `kind = 'video'` | le média lui-même, ses octets et son quota restent gérés ici |
| `agent_tasks` (existante) | colonnes réelles : `id`, `ref`, `title`, `agent_role`, `status`, `priority`, `description`, `result_summary`, `required_permission`, `created_by`, `assigned_to`, `created_at`, `updated_at`, `completed_at` | la phase A y inscrit une tâche `agent_role='video'` et la passe à `done` (ou `failed`) à la fin du sondage, avec un `result_summary` lisible. **Il n'existe ni colonne `type`, ni `payload_json`, ni `result_json`, ni `attempts`, ni `run_after`, ni `locked_by`** — le plan d'exécution asynchrone devra être conçu avec les colonnes réellement disponibles, ou enrichi par une migration explicite |

Le rapport détaillé (pistes, notes, marque, conteneurs compatibles) tient dans `meta_json`,
plafonné à 16 000 caractères. La réduction est faite **sur l’objet, jamais sur le texte**
(`src/utils/json-limit.js`) : tableaux coupés de moitié, longues chaînes tronquées, puis un
marqueur `truncated: true`. Un `JSON.stringify(x).slice(0, n)` produirait du JSON illisible que
le lecteur avalerait en silence — la perte deviendrait invisible. Le dépôt refuse en plus
d’écrire une chaîne qui ne se relit pas (`validJson`) et la remplace par un objet qui déclare la
perte. Les deux comportements sont couverts par des tests.

Index réels : `idx_video_assets_owner (owner_id, deleted_at)`,
`idx_video_assets_status (status, id)`, `idx_video_assets_file (file_id)`,
`idx_video_analyses_video (video_id, kind)` (plus la contrainte `UNIQUE`),
`idx_agent_tasks_role_status (agent_role, status, id)` pour le ramassage de file.

Phase C (migration `006_video_tools.sql`) : aucun nouvel objet — cinq réglages seulement, parce
qu'exécuter un décodeur externe est une capacité que l'administrateur ouvre, pas une variable
d'environnement de plus.

Phase B (migration `005_video_jobs.sql`) : la table `video_jobs` décrite plus haut, avec son
déclencheur `touch_video_jobs_updated_at` et `idx_video_jobs_claim (status, run_after, priority, id)`
— l'index exactement demandé par le prélèvement ; et `files.parent_file_id INTEGER REFERENCES
files(id) ON DELETE CASCADE` + `idx_files_parent`, nullable, qui rattache un artefact (vignette,
piste audio, rapport) à son média source. Un artefact hérite du propriétaire de la source au
moment du dépôt (`files.store` refuse de le faire changer de main, y compris pour un administrateur),
compte dans le même quota, et **disparaît avec elle** : `files.service.remove()` soft-supprime les
enfants et retire leurs octets, sinon une vignette survivrait à la vidéo qu'elle représente.

## Permissions (28ᵉ à 33ᵉ de la liste — total 33, compté dans `data/app.db`)

`videos:upload`, `videos:read`, `videos:read:any`, `videos:process` (catégorie `agents`, `is_dangerous = 0`),
puis phase B : `videos:stream` (ADMIN **et** USER — c'est le droit de lire ses propres octets) et
`videos:manage-jobs` (ADMIN seul — ramasser les bails, purger la file). `ADMIN` reçoit les
quatre ; `USER` reçoit `videos:upload` et `videos:read` **sans** `videos:read:any`
(portée sur ses propres lignes, comme pour les fichiers) ni `videos:process`, ni
`videos:manage-jobs`. Un compte standard peut donc mettre en file et suivre **ses** tâches, pas
décider du sort de celles d'autrui.

## API exposée

```
POST /api/videos                 { fileId }                      → 201 { asset, analysis }   videos:upload
POST /api/videos/upload          multipart `file`                 → 201 { file, asset, analysis, meta }   videos:upload
POST /api/videos/from-url        { url }                           → 501 VIDEO_URL_NOT_IMPLEMENTED        videos:upload
GET  /api/videos                 ?status&q&limit&offset&scope=mine → { items, total, limit, offset }   videos:read
GET  /api/videos/stats           posture de l'agent                → { count, bytes, quarantined, limits }   videos:read
GET  /api/videos/:id             asset + fichier + analyses        → { asset, file, analyses }   portée propriétaire
POST /api/videos/:id/probe       re-sondage                          → { asset, analyses }   videos:upload (portée) ou videos:process
POST /api/videos/:id/quarantine  mise en quarantaine { reason }      → { asset }   videos:process
POST /api/videos/:id/release     levée de quarantaine                → { asset }   videos:process

GET|HEAD /api/videos/:id/stream  lecture par tranches (Range)         → 200/206/304/416   videos:stream + vidéo prête
POST /api/videos/:id/jobs        mettre une tâche en file { kind, input } → 202 { job, limits }   probe : videos:upload ; kinds lourds : videos:process
GET  /api/videos/jobs            file portée (?status&videoId&limit)  → { items, total, scope }   videos:read
GET  /api/videos/jobs/stats      compteurs + bornes du bail           → { queued, running, expiredLeases, limits }   videos:read
GET  /api/videos/jobs/:id        détail d'une tâche                   → { job }   portée propriétaire
POST /api/videos/jobs/:id/cancel annuler                               → { job }   propriétaire ou videos:manage-jobs
POST /api/videos/jobs/:id/retry  remettre en file (tentatives à zéro)  → { job }   idem
POST /api/videos/jobs/reap       ramasser les bails expirés, purge optionnelle { purgeBefore } → videos:manage-jobs
```

L'ordre de déclaration de ces routes est une contrainte, pas un détail : `/jobs`, `/jobs/stats`
et `/jobs/:id` doivent précéder `/:id`, sans quoi `Number('jobs')` ferait un `NaN` et la file
deviendrait injoignable. `tests/video-stream.test.js` le vérifie en appelant réellement
`GET /api/videos/jobs`.

`GET /api/videos/stats` renvoie en plus `streaming` (état réel de `video.stream_enabled`),
`tools` (`{ enabled, binary, limits }` : le commutateur **et** la présence effective de l'outil) et
`jobs` (compteurs de file + bornes effectives), pour que l'interface affiche la capacité
disponible et non une intention.

`input` d'une tâche est un objet **fermé** : `format` (`png` ou `wav`), `atMs`, `width`,
`maxSeconds`, `maxKb` — cinq clés au plus, aucune autre acceptée (400), et le service re-borne tout
de son côté. Une clé inconnue n'est pas tamisée, elle est refusée : une saisie qui traverse
silencieusement la validation devient un jour un paramètre d'outil.

### Outillage média (`src/services/video-ffmpeg.js`, `src/services/video-media.service.js`)

Deux gestes, un seul exécutant : la **vignette PNG** et la **piste audio WAV**, tous deux demandés
par une tâche `thumbnail` dont `input.format` choisit la sortie. La chaîne, dans l'ordre, est la
seule voie permise :

1. `video.tools_enabled` ouvert (sinon 409 `VIDEO_TOOLS_DISABLED`) ;
2. portée vérifiée par `videos.scopedRow()` avec le **propriétaire de la vidéo** comme acteur — le
   worker n'a pas de session et ne reçoit donc aucun super-droit ;
3. `assertReadyForRender` puis `verifiedSource` (les deux portes de la lecture, mêmes fonctions, y
   compris la taille épinglée revérifiée sur disque) ;
4. `resolveBin()` : un exécutable résolu, contrôlé `isFile` + exécutable, sinon 503
   `VIDEO_TOOL_UNAVAILABLE` ;
5. répertoire de travail `0700` créé par `mkdtemp` dans `os.tmpdir()` (`ps-thumb-*`, `ps-audio-*`
   — `tmpfs` monté `noexec` dans la composition), détruit en `finally` même si l'outil a produit
   400 000 octets ; `scratchRoot` est une option du service pour un déploiement qui préfère un
   montage dédié ;
6. exécution : `spawnSync` **sans coquille**, `env` réduit à `PATH`, argv construit à la main
   (seuls entiers bornés et chemins internes ; aucun nom de fichier ni texte client dans la ligne
   de commande), délai dur borné à 5 minutes, plafond d'octets sur la sortie ;
7. relecture et **validation de signature** (`isPng`, `RIFF…WAVE`) puis contrôle de taille, sinon
   rejet 422 `VIDEO_TOOL_OUTPUT_REFUSED` et `unlink` ;
8. `files.store({ parentFileId, maxBytes })` : l'artefact devient une ligne `files` ordinaire,
   soumise à la **même** politique que les téléversements (extension, MIME, `MAGIC`, quota,
   propriétaire, cascade de suppression) — il n'existe aucune porte « confiance serveur » ;
9. audit `video.thumbnail.created` / `video.audio.created`, et `*.refused` en `warning` pour chaque
   refus, y compris les refus de porte ; aucun chemin absolu dans le détail ni dans la colonne
   `error_message` (neutralisé par `utils/sanitize.js`).

Le profil de la piste (`16 000 Hz`, `1` canal) est une constante exportée
(`AUDIO_PROFILE`) : c'est la même valeur qui part dans `argv` et qui revient dans le résultat de
la tâche. Un résultat de `thumbnail` cite `fileId`, `bytes`, `format`, `width`, `atMs`,
`maxBytes` — ce qui a été appliqué, pas ce qui avait été demandé.

### Sémantique de la lecture (`src/services/video-stream.js`)

Les gardes sont dans cet ordre, et le premier qui refuse décide :

1. `video.stream_enabled` vrai — sinon `409 VIDEO_STREAM_DISABLED` (la réponse nomme le réglage à ouvrir) ;
2. `videos.assertEnabled()` — la fonctionnalité vidéo éteinte refuse tout ;
3. `status === 'ready'` — sinon `409 VIDEO_NOT_READY` (quarantaine, échec de sondage ou sondage
   simplement pas encore fait : un job en file ne vaut pas un média vérifié) ;
4. `files.kind === 'video'` **et** `magic_ok = 1` — sinon `403 VIDEO_UNSAFE_SOURCE` ;
5. `statSync` égal à `files.size_bytes` — sinon `409 VIDEO_SIZE_MISMATCH` : un fichier modifié hors
   de l'application n'est plus celui qui a été analysé ;
6. `isFile()` seul compte (pas de lien, pas de périphérique, pas de fifo) ;
7. portée : `videos.scopedRow()` — **la même fonction** que celle qui sert le rapport JSON, donc
   ce que l'on rapporte et ce que l'on débite ne peuvent pas diverger de droit d'accès.

Le type média annoncé vient du conteneur **sondé** (`mp4`, `mov`, `webm`, `mkv`, `avi`, `ogv`),
jamais de l'en-tête `Content-Type` de l'envoi. Une seule plage est honorée ; une plage invraisemblable
(`bytes=1-0`, début hors fichier, queue vide) vaut `416` avec `Content-Range: bytes */taille` ; une
demande multi-plages est traitée comme une absence de plage (réponse complète, conforme à RFC 7233
qui l'autorise) plutôt que comme un `206` trompeur. L'`ETag` est `W/"<16 premiers hex de
sha256>-<taille>"`, et `If-None-Match` répond `304` sans corps. En-têtes de réponse :
`Accept-Ranges`, `Content-Range`, `Content-Length` de la tranche, `Vary: Cookie, Range`,
`X-Content-Type-Options: nosniff`, `Cross-Origin-Resource-Policy: same-origin`,
`Content-Security-Policy: default-src 'none'`, `Content-Disposition: inline; filename="…"`.
Ce dernier nom est assaini caractère par caractère (aucun CR, LF, guillemet, contre-oblique,
ni octet de contrôle) et tronqué à 120 : un nom de fichier téléversé ne peut pas injecter
d'en-tête.

Le corps est écrit par `fs.createReadStream(abs, { start, end })` — jamais `readFile` entier — et
`req.on('aborted'|'close')` détruit le flux : un lecteur qui cherche une position ne laisse pas un
descripteur ouvert.

### File d'exécution

`video_jobs` (migration `005_video_jobs.sql`) porte le bail, pas `agent_tasks` :

| Colonne | Rôle |
|---|---|
| `video_id`, `file_id`, `owner_id` | la cible et le porteur du droit ; `UNIQUE(video_id, kind)` rend la mise en file **idempotente** (redemander un `probe` requalifie la ligne au lieu d'empiler) |
| `kind` | `probe`, `transcode`, `transcribe`, `thumbnail`, `moderation` — liste fermée, vérifiée en base par `CHECK` |
| `status` | `queued`, `running`, `succeeded`, `failed`, `cancelled` |
| `locked_by`, `locked_at`, `lease_expires_at` | preneur unique : le `claim` est un `UPDATE ... WHERE id = ? AND status = 'queued'` dans une transaction, deux workers ne gagnent pas tous les deux |
| `attempts`, `max_attempts`, `run_after` | Rechutes bornées : `attempts` est incrémenté à la prise, l'échec repousse `run_after` d'un backoff doublant à chaque tentative ; à `max_attempts` la tâche passe `failed` |
| `priority` | 0 à 9 (`CHECK`), prélèvement `ORDER BY priority DESC, id ASC` |
| `input_json`, `result_json` | bornés (30 000 octets) par la même politique que les rapports d'analyse |
| `error_code`, `error_message` | le message est nettoyé : chemins absolus, `file://` et lecteurs Windows sont remplacés, puis `redact` passe — un `EIO` sur `/home/…/data/uploads/x.mp4` ne doit pas apprendre à un client où est le stockage |

Un bail expiré est **repris** (`reapExpired`, lot de 500 maximum par tour, pour qu'une panne
prolongée ne transforme pas un tick en balayage de dizaines de milliers de lignes) ; un worker
qui revient après son bail obtient `{ lost: true }` et son résultat n'est **pas** écrit.
`kinds` borne le prélèvement : un worker configuré `VIDEO_WORKER_KINDS=probe` ne saisit pas une
`thumbnail`, il la laisse à un worker capable. Un kind sans exécuteur n'est pas un succès vide :
`VIDEO_TOOL_UNAVAILABLE`, relance repoussée, échec nommé.

`npm run worker` (ou `worker:once` pour un tour) lance `scripts/video-worker.js` ; le service
`worker` de `docker-compose.yml` le fait tourner avec `network_mode: "none"`, `pids-limit: 128`,
`mem_limit: 512m`, `cpus: "1.0"`, et aucun accès réseau — le processus qui touche aux octets du
média est séparé de celui qui sert l'interface.

Codes d'erreur (forme `AppError`, jamais de sortie brute) : `VIDEO_FEATURE_DISABLED` (409, fonctionnalité
éteinte), `VIDEO_NOT_A_VIDEO` (400, le fichier n’est pas de type `video`),
`VIDEO_UNSUPPORTED_CONTAINER` (415), `VIDEO_HEADER_INCOMPLETE` (422),
`VIDEO_DURATION_EXCEEDED` (422, mis en quarantaine), `VIDEO_DIMENSIONS_INVALID` (422),
`VIDEO_PROBE_FAILED` (422), `VIDEO_QUARANTINED` (409), `VIDEO_URL_NOT_IMPLEMENTED` (501) ;
phase B : `VIDEO_STREAM_DISABLED` (409), `VIDEO_NOT_READY` (409), `VIDEO_SIZE_MISMATCH` (409),
`VIDEO_UNSAFE_SOURCE` (403), `VIDEO_STREAM_FAILED` (500, erreur d'entrée-sortie en cours de
débit), et côté file `VIDEO_JOB_NOT_ALLOWED`, `VIDEO_JOB_BUSY`, `VIDEO_TOOL_UNAVAILABLE` (503),
`VIDEO_LEASE_LOST`, `VIDEO_LEASE_EXPIRED`, `VIDEO_CANCELLED`, `VIDEO_JOB_FAILED`.
plus les codes hérités du pipeline de fichiers et de l’authentification : `PAYLOAD_TOO_LARGE`
(413 — c’est lui qui fait foi pour la taille, la limite appliquée aux vidéos étant le
`min(MAX_UPLOAD_MB, VIDEO_MAX_UPLOAD_MB)` calculé au démarrage), `UNSUPPORTED_MEDIA_TYPE`
(415), `NOT_FOUND` (404), `FORBIDDEN` (403), `BAD_REQUEST` (400). Un `ffprobe` configuré mais
introuvable ne produit **aucun** code d’erreur : le rapport d’en-têtes est conservé et
`meta.notes` l’explique. Jamais la sortie brute de l’outil : les traces techniques restent
dans le journal.

## Configuration réelle

Variables d'environnement (déclarées dans `.env.example`, sinon le lint refuse) :
`VIDEO_MAX_UPLOAD_MB=64`, `VIDEO_MAX_DURATION_S=3600`, `VIDEO_PROBE_WINDOW_KIB=512`,
`VIDEO_PROBE_TIMEOUT_MS=10000`, `VIDEO_USE_FFPROBE=1`, `FFPROBE_PATH=ffprobe`,
`VIDEO_QUARANTINE_ON_FAILURE=1`. Il n'existe **pas** de `VIDEO_ENABLED` d'environnement : le
 seul commutateur est le réglage en base, pour qu'un administrateur puisse l'activer sans
redéploiement. La limite de téléversement appliquée aux vidéos est
`min(MAX_UPLOAD_MB, VIDEO_MAX_UPLOAD_MB)` — la limite globale commande d'abord, un écart est
signalé au démarrage par `config.video.warning`. C'est ce minimum qui est annoncé à `multer`
(`limits.fileSize`) : le refus a donc lieu **pendant** la lecture du corps, et non après avoir
stocké 10 Mo en mémoire pour les jeter juste après. Le formulaire n'accepte qu'un champ
fichier (`fields: 1`).

Variables ajoutées par la phase B : `VIDEO_WORKER_KINDS=probe` (liste fermée — tout kind
inconnu est écarté au chargement, pas reporté au worker), `VIDEO_WORKER_POLL_MS=1000`,
`VIDEO_WORKER_IN_PROCESS=0` (cadence et périmètre du worker ; le mode « dans le processus web »
n'existe pas, et ce réglage ne le permet pas).

Variables ajoutées par la phase C : `FFMPEG_PATH=ffmpeg` (nom ou chemin du binaire ; il traverse
`safeBinaryPath`, le même contrôle que `FFPROBE_PATH` : pas de métacaractère, pas de traversée,
`isFile` + exécutable) et `VIDEO_TOOL_TIMEOUT_MS=30000`, borné à la lecture entre 1 000 et
300 000 ms — un délai déraisonnable est écrêté, pas honoré.

Réglages en base (page Configuration, validés par `settings.service`) : `video.enabled`
(booléen, `false` par défaut), `video.max_duration_seconds` (entier 1–86400, `3600`),
`video.use_ffprobe` (booléen, `true`) ; phase B : `video.stream_enabled` (`false`),
`video.async_probe` (`false`), `video.lease_seconds` (5–3600, `120`), `video.max_attempts`
(1–10, `3`), `video.backoff_seconds` (0–3600, `2`), `video.worker_concurrency` (1–8, `1`) ; phase C
(migration `006_video_tools.sql`) : `video.tools_enabled` (`false`), `video.thumbnail_width`
(32–1920, `320`), `video.thumbnail_at_ms` (0–86 400 000, `1000`), `video.thumbnail_max_kb`
(8–65 536, `512`), `video.audio_max_seconds` (1–3600, `300`).
**24 réglages au total**, comptés dans `data/app.db` (`SELECT count(*) FROM settings` après
application des six migrations) : 19 en sortie des phases A et B, 5 ajoutés par `006_video_tools.sql`. Ce sont eux qui ouvrent ou ferment les
modes — pas une variable d'environnement de plus : un administrateur doit pouvoir refermer la
lecture en continu sans redéployer, et le worker lit sa cadence dans l'environnement parce que
c'est une propriété du processus, pas une décision métier.

## Critères d'acceptation prouvés par les tests

`tests/videos.test.js` — 28 sous-tests, tous verts, exécutés par `npm run check` :

1. refus de toute déclaration tant que `video.enabled` est faux, puis acceptation après
   activation par `PUT /api/admin/settings` ;
2. géométrie réellement restituée pour MP4, WebM, AVI (durée, dimensions, codec, nombre de
   pistes lus dans l'en-tête construit par le test, confronté au parseur) ;
3. relit un MP4 dont la `moov` est en fin de fichier (fenêtre de queue) ;
4. faux `.mp4` refusé à l'ingestion, PNG renommé `.mp4` refusé à l'entrée vidéo directe
   (`415`), rien d'écrit en base ;
5. durée hors limite → `quarantined` + `error_code`, **avec conteneur, dimensions et lecteur
   conservés dans le rapport**, levée exigeant `videos:process` (403 pour `USER`, 200 pour
   `ADMIN`) ; une vidéo jamais sondée levée de quarantaine repasse en `pending`, jamais en
   `ready` ;
6. un compte standard ne lit pas la vidéo d'un autre (403 + liste filtrée), identifiant
   inconnu → 404, tentative de déclarer le fichier d'autrui → 403, aucun chemin serveur dans
   la réponse ;
7. idempotence de la déclaration (aucune ligne ni octet dupliqué), re-sondage qui met à jour
   le rapport `probe` sans doubler la ligne ;
8. `from-url` → 501 explicite ;
9. aucune empreinte complète ni chemin d'aucune sorte dans les rapports ;
10. suppression logique du fichier source → actif soft-supprimé, et la requête de l'auteur
    comme la vue globale renvoient 404 ;
11. `ffprobeRunner` injecté : le rapport `header+ffprobe` est fusionné, l'argument passé est
    le **chemin de stockage**, jamais le nom fourni par le client ; un chemin de binaire
    douteux, un délai expiré ou une exécution impossible font retomber sur le sondage d'en-
    têtes avec une note, sans faute 500 ;
12. `safeBinaryPath` refuse les métacaractères, la traversée et les binaires absents ;
13. `fromFfprobe` borne les valeurs (débit > 1 Tbit/s, pistes > 64, méta > 64 Kio) ;
14. les contraintes `CHECK` de la base refusent durée négative, statut et source inconnus ;
15. `audit_logs` journalise le sondage avec l'empreinte tronquée, sans `/var`/`/srv`/
    `/app`/`/home` ;
16. conteneur inconnu → `ok:false` + `errorCode`, sans exception ;
17. `/api/videos/stats` expose compteurs et bornes effectives ;
18. un rapport démesuré (4 000 pistes, 400 notes de 400 caractères) reste **valide et borné**
    en base, avec `truncated: true` ; une chaîne volontairement cassée soumise au dépôt est
    remplacée par un objet honnête, jamais stockée telle quelle.

## Ce que la phase B a produit de mesuré

* `tests/video-stream.test.js` — **23 sous-tests** verts : découpage de plage en unitaire
  (dont `bytes=1-0`, queue vide, multi-plage), comparaison **octet par octet** contre `fs.readFileSync`
  pour quatre formes de plage, `416` sans corps, `304`, `HEAD` à zéro octet, les sept gardes de la
  route, le `VIDEO_SIZE_MISMATCH` provoqué en tronquant réellement le fichier, claim exclusif,
  isolement par kinds, bail expiré repris, écriture interdite au worker décroché, backoff mesuré sur
  `run_after` (et non contourné par un réglage), échec définitif à `max_attempts`, message d'erreur
  sans chemin, idempotence `UNIQUE(video_id, kind)`, purge journalisée, portée du bordereau de file,
  artefacts rattachés et emportés par la suppression, bornes `CHECK` de la table, permissions.
* E2E contre le **serveur en cours d'exécution** et un **processus worker séparé**
  (`scripts/video-worker.js --once`, lancé par `npm run worker:once`) : **21/21** — dont rapport
  laissé `pending` par la requête puis rempli par le worker, lecture de 200 434 octets par
  tranches, refus du kind lourd par un worker qui ne le connaît pas puis refus nommé par celui qui
  le connaît, et rotation du mot de passe administratif au premier accès.
* `npm run smoke` sur la même instance : **40 contrôles** dont 7 sur la phase B ; `npm run check` :
  lint sans reproche, **248 tests** verts, audit de sécurité sur 115 fichiers, 0 constat.
* `docker compose config` : **ACTION NON EXÉCUTÉE, RAISON : ni `docker` ni `podman` dans cet
  environnement**. Le service `worker` de `docker-compose.yml` a donc été relu à la main (clés,
  ancre `image`, `network_mode: none`, limites, `depends_on: app: service_healthy` pour ne pas
  entrer en concurrence avec les migrations au démarrage), mais sa validation formelle par
  l'outil reste à faire sur une machine qui l'a.

## Ce que la phase C a produit de mesuré

* `tests/video-tools.test.js` — **23 sous-tests** verts, dont une exécution **réelle** d'un
  processus : un shim POSIX (`/bin/sh`, écrit par le test dans un dossier temporaire) est désigné
  comme `FFMPEG_PATH` et se comporte comme un outil — parfois bien, parfois mal. Sont vérifiés :
  argv sans aucun mot venant du client et bornes des deux côtés, scratch `0700` dont un nom
  d'évasion ne sort pas, sortie trop volumineuse **jetée du disque** avec le compte rendu des octets,
  **SIGKILL au délai** (mesuré, pas décrété), code de sortie non nul traduit sans recopier le chemin
  de stockage, sortie absente, vide ou qui n'est pas un PNG, refusée, `shell` jamais utilisé (un nom porteur de
  métacaractères ne fait pas exécuter de commande secondaire), les six portes du service, le
  rattachement et la relecture en ligne de l'artefact, le WAV passé par la même politique que les
  téléversements (`magic_ok` exigé), le refus de capacité **journalisé**, la relecture des paramètres
  de tâche, et 404 non bavard sur une vidéo inexistante.
* Le service est exercé **par HTTP** : `POST /:id/jobs` avec `input` (202, idempotence, refus des
  clés inconnues), exécution par `createVideoJobRunner`, `result` relisible, et `503` nommé quand
  l'outil disparaît du serveur alors que la capacité reste ouverte — les deux états sont distincts.
* E2E contre un **serveur vivant** et un **processus worker vivant** (`/home/user/phase-c-e2e.mjs`,
  hors dépôt) : **19/19** — capacité fermée annoncée par `/api/videos/stats`, acceptation d'une tâche
  quand même puis refus nommé, reprogrammation à retardement sous `max_attempts` (et échec terminal
  à `video.max_attempts = 1`), vignette produite avec `width`/`atMs`/`maxBytes` réellement appliqués,
  PNG relu par la route de contenu, WAV relu en `audio/wav`, sortie non-image jetée sans ligne
  orpheline, plafond de taille cité dans la raison, outil pendant tué en 2,5 s sans faire tomber le
  serveur, artefact invisible à un autre compte (403) et à l'anonyme (401), audit cohérent, et
  **aucun chemin absolu** dans les 19 000 octets de réponses capturées ni dans le journal serveur.
* `npm test` : **271 tests, 37 suites, 0 échec** (13 fichiers) ; `npm run check` : lint sans
  reproche, audit de sécurité sur **120 fichiers** de l'arbre suivi (121 avec un `.env` local), 0 constat, `npm audit` 0 vulnérabilité ;
  `npm run smoke` sur instance fraîche : **42 contrôles OK, 0 échec, 0 non exécuté** ;
  `npx vite build` : 18 fichiers JSX compilés.
* Nouvelle mesure le 2026-10-04, après les durcissements d’en-têtes et la porte 401 sur
  `POST /api/auth/change-password` : `npm run check` à 0 (274 tests, 38 suites, audit sans
  constat), `npm run smoke` **40/40** sur une instance fraîche aux réglages durcis, et parcours
  de mise en service **37/37** (détail dans docs/TESTING.md). Le fichier de workflow reste
  à copier sous `.github/workflows/ci.yml` : la tentative a été poussée le 2026-10-04 et
  GitHub l'a refusée (`refusing to allow a GitHub App to create or update workflow
  .github/workflows/ci.yml without workflows permission`).
* Deux défauts que seuls ces tests ont trouvés, et qui sont donc écrits dans le code plutôt que
  dans un commentaire : `jobInput` n'était pas **idempotent** (un appel direct perdait `width` et
  retombait sur le réglage, sans erreur nulle part), et le worker **filtrait** le résultat du
  service, ce qui vidait `result` des grandeurs appliquées — la chaîne complète les montre désormais.
* `docker compose config` : **ACTION NON EXÉCUTÉE, RAISON : ni `docker` ni `podman` dans cet
  environnement**. La politique du service `worker` (limites, `network_mode: none`) n'a donc pas changé
  en phase C et reste relue à la main seulement.

## Contraintes structurantes conservées pour les phases B à D

Aucun transcodage dans le processus web. `ffmpeg` est un binaire externe, gourmand et
historiquement attaquable par fichier malformé : le média sera traité par un **worker
séparé**, dans un conteneur à part, avec système de fichiers en lecture seule sauf un
répertoire de travail `tmpfs` monté `noexec`, `cap_drop: [ALL]`, `no-new-privileges`,
`network_mode: "none"`, utilisateur non root, limites `cpus`/`pids`/`memory`, délai dur,
environnement vidé (`env -i`), et **aucun argument issu de l'utilisateur dans la ligne de
commande**. Le re-sondage par `ffprobe` d'une phase à l'autre garde les mêmes bornes.

* **Phase B — faite** : flux `Range` authentifié (206/416/304), file d'exécution propre
  (`video_jobs` : claim sous transaction, bail, backoff, idempotence), artefacts rattachés par
  `files.parent_file_id`. Le worker est un **autre processus**, sans réseau ; le processus web
  débite des octets mais ne traite jamais un média.
* **Phase C — faite (à moitié annoncée comme telle, à moitié en attente)** : vignettes et piste
  audio via le worker, sous les neuf étapes ci-dessus. Reste à faire, et non simulé : la
  **transcription** (aucun modèle ASR branché — `transcribe` est un refus nommé qui refile la tâche
  au lieu de la marquer réussie), le texte qui, lui, passera par `redactHits` avant stockage, et la
  politique de conservation de l'audio (aujourd'hui l'artefact `files` vit et meurt avec sa source).
* **Phase D** — collecte par URL (réutilise `assertSafeUrl`, re-vérification du nom résolu
  contre le rebind DNS, plafond de taille et de durée pendant le téléchargement), modération
  légère, rapports composites.

## Risque principal restant

Le sondage est **déclaratif** : il lit ce que l'en-tête annonce. Un fichier peut mentir dans
son en-tête sans que la phase A le détecte ; c'est précisément pourquoi un résultat
incohérent met en quarantaine et n'autorise aucun rendu. La vérification par décodage réel reste à
la phase C, dans le worker.

La phase C déplace le risque, elle ne le supprime pas : `ffmpeg` est un binaire de plusieurs
centaines de milliers de lignes, historiquement attaquable par fichier malformé, et **ce dépôt
n'exécute aucun vrai `ffmpeg` en test** (aucun n'est installé ici). L'enveloppe est prouvée — pas la
résistance du décodeur. Les compensations en place : capacité fermée par défaut, exécution dans le
seul worker (`network_mode: none`, CPU/pids/mémoire bornés dans `docker-compose.yml`), argv fermé,
délai dur, plafond de sortie, signature exigée avant stockage, et rattrapage par le bail si le
processus meurt ailleurs que dans le bac à sable.

Conséquence assumée de la phase B : débiter des octets ne prouve pas que le fichier se décode. La
route ouvre donc l'octet à un compte authentifié qui a le droit de lire **ce** fichier, sans
exécuter ni parser le média dans le processus web — le risque résiduel est la consommation de
bande passante et la lecture d'un fichier malveillant par le **lecteur du navigateur**, pas
l'exécution côté serveur. Les leviers en place : capacité fermée par défaut, plafond de taille à
l'entrée, quarantaine réversible par l'administration, `magic_ok` exigé, taille épinglée sur
`files.size_bytes`, et aucun média traité dans le processus qui sert l'interface.
