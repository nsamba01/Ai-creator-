# Agent Vidéo — architecture prévue

> **Statut : non implémenté.** Ce document est la conception validée pour la suite du
> chantier. Rien de ce qui suit n'est présent dans le code à ce jour ; rien ne doit être
> présenté comme fonctionnel. La section « Critères d'acceptation » est ce qui devra être
> démontré par des tests pour que l'agent vidéo soit considéré comme terminé.

## Objectif

Permettre à un utilisateur autorisé de confier une vidéo (téléversée ou adressée par URL)
à un agent qui produit : un rapport technique (conteneur, flux, codecs, durée, débit,
résolution, fréquence d'images), une extraction audio et une transcription, une planche de
vignettes, une détection de parties silencieuses/noires, et une modération légère (liste
d'interdits, présence de texte incrusté) — **sans jamais exécuter le média ni ouvrir de
chemin arbitraire**.

## Contrainte structurante n° 1 : sortir du processus web

Aucun transcodage dans le serveur d'application. `ffmpeg`/`ffprobe` sont des binaires
externes, gourmands, et historiquement attaquables par fichier malformé. Le média est donc
traité par un **worker séparé**, dans un conteneur à part, avec :

* système de fichiers en lecture seule, sauf un répertoire de travail `tmpfs` monté `noexec`
  **sauf** le sous-répertoire d'entrée, monté `noexec,nosuid,nodev` en lecture seule ;
* `cap_drop: [ALL]`, `no-new-privileges`, aucun accès réseau (`network_mode: "none"`),
  utilisateur non root, limites `cpus`, `pids`, `memory` ;
* exécution avec un **délai dur** (`timeout`), une taille maximale en amont, et un
  environnement vidé (`env -i`) ;
* **aucun argument issu de l'utilisateur dans la ligne de commande** : uniquement le chemin
  interne calculé par le serveur (UUID), passé après un `--`, et re-vérifié par
  `resolveStored()` ; l'analyse d'URL réutilise `assertSafeUrl` (SSRF) avant tout
  téléchargement ;
* `ffprobe` d'abord (métadonnées seules), traitement seulement si les métadonnées sont
  cohérentes (format sur liste blanche, durée ≤ `VIDEO_MAX_DURATION_S`, pas de flux de
  données suspicieux).

## Chaîne de traitement

```
             (1) ingest                    (2) probe                 (3) transform
API ──► files (kind=video) ──► agent_tasks (queued) ──► worker ──► ffprobe JSON ──► ffmpeg
   │                                                            │        borné
   │                                                            ▼
   └──► audit + quota                                    (4) audio → ASR/sous-titres
                                                              │
                                                              ▼
                                                   (5) artefacts : vignettes, waveforms,
                                                       transcription, rapport
                                                              │
                                                              ▼
                                                   (6) écriture du résultat + events d'audit
```

1. **Ingestion** : le média entre par le pipeline de fichiers existant (liste blanche
   d'extensions `.mp4 .m4v .mov .mkv .webm .avi`, types MIME conteneurs, contrôle des
   octets signatures de tête : `ftyp`, `EBML`, `RIFF….AVI `, `matroska`), taille
   `VIDEO_MAX_UPLOAD_MB`, quota `MAX_QUOTA_MB`, nommage UUID, propriétaire = l'utilisateur.
   `video/*` doit rejoindre `KIND_BY_EXT` de `src/services/files.service.js`, rester absent de
   `FORBIDDEN_EXTENSIONS`, obtenir une famille dans `MIME_FAMILIES` et une entrée dans `MAGIC`
   (signatures de tête) ; la règle d'exécution reste « le fichier n'est
   jamais servi pour lecture dans le navigateur » (l'élément `<video>` lira par l'API
   authentifiée avec `Range`, jamais par une route statique publique).
2. **Sondage** : `ffprobe -v error -print_format json -show_format -show_streams` borné à
   10 s et 1 Mio de sortie ; rejet d'un fichier déclarant une durée ou un débit aberrants.
3. **Transformation** : `ffmpeg` appelé avec une grille de recettes fermée
   (`poster-3x3`, `audio-16k-mono`, `preview-720p`) — jamais de paramètres utilisateur
   libres ; découpage par `-ss`/`-t` bornés, sortie dans le répertoire de travail, puis
   promotion atomique vers le stockage.
4. **Transcription** : `whisper.cpp` (ou équivalent local) dans le conteneur worker, modèle
   chargé en lecture seule, langue par défaut `auto`, texte re-passé par la politique de
   secret (`redactHits`) avant stockage ; l'audio n'est jamais conservé si
   `VIDEO_KEEP_AUDIO=0` (défaut).
5. **Artefacts** : chaque sortie devient une ligne `files` à part entière (même
   `owner_id`, `sha`, `size_bytes`, `scan_status`) pour réutiliser le contrôle d'accès, le quota
   et la suppression ; l'ajout d'une colonne `parent_file_id` (nullable, `ON DELETE CASCADE`)
   dans la migration `004` est nécessaire pour rattacher l'artefact à sa source — elle
   n'existe pas aujourd'hui.
6. **Rapport** : agrégation dans `document_analyses` (ou `video_analyses`) + événement
   d'audit ; le statut de la tâche est consultable (`GET /api/agents/tasks/:id`) et le
   rapport se télécharge comme n'importe quel fichier.

## Modèle de données additionnel (migration `004_video_agent.sql`)

| Table | Colonnes utiles | Notes |
|---|---|---|
| `video_assets` | `file_id` (FK → `files`), `container`, `duration_ms`, `width`, `height`, `fps`, `bitrate`, `streams_json`, `probed_at`, `status` | `status ∈ (pending, probing, ready, failed, quarantined)` ; `CHECK` sur les bornes de durée/taille |
| `video_analyses` | `video_id`, `kind`, `result_json`, `model`, `cost_ms`, `created_at` | un `kind` par recette ; `result_json` réduit avant stockage |
| `agent_tasks` (existant) | `type='video.probe' \| 'video.transcode' \| 'video.transcribe'` | **la file existante sert de planeur** : `queued → running → succeeded/failed`, `attempts`, `run_after` (retry exponentiel), `locked_by`, `locked_at` |
| `video_thumbnails` | `video_id`, `at_ms`, `file_id`, `width`, `height` | vignettes stockées comme fichiers, donc soumises au quota |

Index prévus : `video_assets(status)`, `agent_tasks(type, status, run_after)` pour le
ramassage, `video_analyses(video_id, kind)` unique.

## Permissions nouvelles (28ᵉ à 30ᵉ)

`videos:upload`, `videos:read:any`, `videos:process`. `ADMIN` les reçoit, `USER` reçoit
`videos:upload` et `videos:read:any` **absent** (portée sur ses propres lignes, comme pour
les fichiers). La file de tâches reste pilotée par `agents:manage`.

## API visée

```
POST /api/videos                 { fileId } ou { url }      → 202 { taskId }   videos:upload
GET  /api/videos/:id             rapport + flux + vignettes  portée propriétaire
GET  /api/videos/:id/stream      lecture Range authentifiée  portée propriétaire
POST /api/videos/:id/retry       remise en file              videos:process
GET  /api/agents/tasks/:id       statut, progression, erreurs normalisées
```

Réponses d'erreur : `VIDEO_TOO_LARGE`, `VIDEO_UNSUPPORTED_CONTAINER`, `VIDEO_PROBE_FAILED`,
`VIDEO_BUSY` (quota de tâches parallèles par utilisateur), dans la forme `AppError`
existante — jamais de sortie `ffmpeg` brute (les traces technique restent dans le journal).

## Configuration prévue (à ajouter à `.env.example`, le lint l'exige)

`VIDEO_MAX_UPLOAD_MB=200`, `VIDEO_MAX_DURATION_S=3600`, `VIDEO_WORKER_CONCURRENCY=1`,
`VIDEO_TASK_TIMEOUT_MS=600000`, `VIDEO_KEEP_AUDIO=0`, `VIDEO_ALLOW_PRIVATE_SOURCES=0`
(reprend la sémantique SSRF), `VIDEO_THUMBNAIL_COUNT=9`.

## Critères d'acceptation (à prouver par les tests)

1. Un fichier qui n'est pas une vidéo mais porte une extension de vidéo est **refusé** aux
   signatures binaires ; un fichier de plus de `VIDEO_MAX_UPLOAD_MB` est refusé avant écriture.
2. Une URL vers `169.254.169.254`, `[::ffff:127.0.0.1]`, `host.docker.internal` est refusée
   avant tout téléchargement ; le nom résolu est re-vérifié (rebind DNS).
3. Aucun argument utilisateur n'atteint la ligne de commande : le test doit pouvoir tenter
   `; rm -rf /`, `$(id)`, `-vf` injecté dans un nom de fichier, et montrer qu'ils sont traités
   comme des noms de stockage, pas comme des commandes.
4. Une tâche qui dépasse son délai est tuée par le `timeout` du worker, l'occupant est
   relâché (`locked_by` remis à zéro), la tâche repasse en `queued` avec `attempts + 1`,
   puis échoue définitivement après 3 tentatives sans laisser de fichier orphelin.
5. Un worker qui meurt en cours de tâche ne bloque pas la file : rattrapage par
   `locked_at` expiré (test avec `run_after` forcé).
6. Le quota par utilisateur est respecté pour la source **et** les artefacts ; la suppression
   de la source supprime logiquement les artefacts et retire les octets du disque.
7. Deux utilisateurs ne peuvent ni lire ni relancer la tâche de l'autre (403 par
   `requirePermission` + portée), y compris via l'identifiant de tâche.
8. Une transcription contenant une clef privée ou un jeton est stockée réduite, et
   l'audit ne contient pas le texte.
9. `GET /api/videos/:id/stream` honore `Range`, renvoie `416` hors plage, et reste refusé
   sans session valide.
10. Le rapport complet est régénérable : rejouer une tâche ne duplique pas de données
    (contrainte unique `(video_id, kind)`).

## Découpage proposé

| Phase | Contenu | Risque principal |
|---|---|---|
| A | `004_video_agent.sql`, `kind` vidéo, liste blanche d'extensions, rapport `ffprobe` seul (**aucun transcodage**) | faible — lecture seule, pas d'écriture de média |
| B | worker conteneur + file (claim, timeout, retries, idempotence) | concurrence et tâches orphelines |
| C | vignettes + audio + transcription | coût CPU, poids du modèle ASR |
| D | modération légère, rapports composites, interface `client/pages/Videos.jsx` | surface UX |

Phase A est livrable sans le moindre binaire externe supplémentaire si `ffprobe` est rendu
optionnel : en son absence, le rapport se limite à l'en-tête du conteneur (boîtes `ftyp`
explorées en JS), ce qui reste utile et ne change rien au modèle de sécurité.
