# Agent Vidéo — architecture

> **Statut : phase A implémentée et testée ; phases B à D en conception.**
> Ce document décrit d'abord ce qui est réellement dans le code (avec les chemins de
> fichiers), puis ce qui reste à faire. Toute ligne qui n'est pas écrite est marquée
> « prévu » ; rien n'est présenté comme fonctionnel sans test correspondant.

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
   quarantaine — chaque action étant re-décidée par le serveur.

## Ce que la phase A ne fait pas (à ne pas vendre)

* **aucun lecteur, aucun flux** : pas de `GET /api/videos/:id/stream`, pas de `Range`. Une
  balise `<video>` sur une route non authentifiée serait une fuite ; la lecture en continu
  authentifiée est la phase B ;
* **aucun transcodage, aucune vignette, aucune transcription** : ni `ffmpeg`, ni ASR, ni
  modèle chargé ;
* **aucun collecte par URL** : `POST /api/videos/from-url` répond `501 NOT_IMPLEMENTED` —
  l'agent de collecte refuse délibérément de télécharger un média tant que le bac à sable du
  worker n'existe pas ;
* **aucun plan d'exécution asynchrone** : le sondage est synchrone, borné à une fenêtre de
  lecture, et ne crée pas de tâche `agent_tasks` (le champ `task_id` est posé, relié à la
  phase B).

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

## Permissions (28ᵉ à 31ᵉ de la liste — total 31)

`videos:upload`, `videos:read`, `videos:read:any`, `videos:process` (catégorie `agents`, `is_dangerous = 0`). `ADMIN` reçoit les
quatre ; `USER` reçoit `videos:upload` et `videos:read` **sans** `videos:read:any`
(portée sur ses propres lignes, comme pour les fichiers) ni `videos:process`. La file de
tâches reste pilotée par `agents:manage`.

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
```

Codes d'erreur (forme `AppError`, jamais de sortie brute) : `VIDEO_FEATURE_DISABLED` (409, fonctionnalité
éteinte), `VIDEO_NOT_A_VIDEO` (400, le fichier n’est pas de type `video`),
`VIDEO_UNSUPPORTED_CONTAINER` (415), `VIDEO_HEADER_INCOMPLETE` (422),
`VIDEO_DURATION_EXCEEDED` (422, mis en quarantaine), `VIDEO_DIMENSIONS_INVALID` (422),
`VIDEO_PROBE_FAILED` (422), `VIDEO_QUARANTINED` (409), `VIDEO_URL_NOT_IMPLEMENTED` (501),
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

Réglages en base (page Configuration, validés par `settings.service`) : `video.enabled`
(booléen, `false` par défaut), `video.max_duration_seconds` (entier 1–86400, `3600`),
`video.use_ffprobe` (booléen, `true`).

## Critères d'acceptation prouvés par les tests

`tests/videos.test.js` — 23 sous-tests, tous verts, exécutés par `npm run check` :

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

## Contraintes structurantes conservées pour les phases B à D

Aucun transcodage dans le processus web. `ffmpeg` est un binaire externe, gourmand et
historiquement attaquable par fichier malformé : le média sera traité par un **worker
séparé**, dans un conteneur à part, avec système de fichiers en lecture seule sauf un
répertoire de travail `tmpfs` monté `noexec`, `cap_drop: [ALL]`, `no-new-privileges`,
`network_mode: "none"`, utilisateur non root, limites `cpus`/`pids`/`memory`, délai dur,
environnement vidé (`env -i`), et **aucun argument issu de l'utilisateur dans la ligne de
commande**. Le re-sondage par `ffprobe` d'une phase à l'autre garde les mêmes bornes.

* **Phase B** — `GET /api/videos/:id/stream` authentifié avec `Range` (206/416), plan d'exé-
  cution asynchrone sur `agent_tasks` (claim, délai, reprise après incident, idempotence),
  artefacts rattachés par une colonne `parent_file_id` de `files` (nullable,
  `ON DELETE CASCADE` — elle n'existe pas aujourd'hui).
* **Phase C** — vignettes (`thumbnail`), extraction audio et transcription locale ; le texte
  produit repasse par la politique de secret (`redactHits`) avant stockage, et l'audio n'est
  pas conservé par défaut.
* **Phase D** — collecte par URL (réutilise `assertSafeUrl`, re-vérification du nom résolu
  contre le rebind DNS, plafond de taille et de durée pendant le téléchargement), modération
  légère, rapports composites.

## Risque principal restant

Le sondage est **déclaratif** : il lit ce que l'en-tête annonce. Un fichier peut mentir dans
son en-tête sans que la phase A le détecte ; c'est précisément pourquoi un résultat
incohérent met en quarantaine et n'autorise aucun rendu. La vérification par décodage réel
reste à la phase B/C, dans le worker.
