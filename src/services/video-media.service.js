/**
 * Traitement hors-bande d'une vidéo : vignette PNG et piste audio WAV (phase C de l'agent vidéo).
 *
 * Ce service n'est jamais appelé par une route qui sert une page : il est appelé par le WORKER, sur
 * une tâche déjà acceptée en file. Le processus web, lui, ne débite que des octets déjà validés.
 * Cette séparation est la raison d'être du module — un décodeur ne doit pas tourner dans ce qui
 * tient la session d'un utilisateur.
 *
 * Quatre héritages de conception, tous vérifiés par tests :
 *  - la **même politique de source** que la lecture (`video-source.js`) : on ne fabrique pas une
 *    vignette d'un fichier remplacé sur disque depuis son analyse ;
 *  - la sortie de l'outil ne devient un fichier que si elle est **petite et signée** (PNG ou WAV) :
 *    un ffmpeg piégé qui écrirait autre chose reste dans un répertoire 0700 détruit en `finally` ;
 *  - l'artefact naît **rattaché à sa source** (`parentFileId`) : même propriétaire, même quota, et
 *    la suppression de la vidéo emporte la vignette ;
 *  - l'acteur du worker est **le propriétaire de la tâche**, pas un super-compte : aucune inflation
 *    de droit ne vient du fait que le code tourne hors requête.
 */
import os from 'node:os';
import path from 'node:path';
import { AppError, badRequest, notFound } from '../utils/errors.js';
import { binaryNameShape, safeBinaryPath } from './video.service.js';
import { assertReadyForRender, verifiedSource } from './video-source.js';
import { audioArgs, AUDIO_PROFILE, createFfmpegRunner, isPng, makeScratch, thumbnailArgs, TOOL_ERRORS } from './video-ffmpeg.js';
import { safeMessage } from '../utils/sanitize.js';

export const MEDIA_ERRORS = TOOL_ERRORS;

/**
 * Plafond absolu d'une piste, aligné sur celui du lanceur (`createFfmpegRunner`). À 16 kHz mono,
 * 64 Mio correspondent à environ 34 minutes d'audio : une demande plus longue que ce que le
 * réglage `video.audio_max_seconds` autorise (jusqu'à 60 minutes) est donc **refusée sur le
 * plafond**, avec les deux chiffres dans la raison — jamais tronquée en silence, jamais lue en
 * entier dans un conteneur borné à 512 Mio.
 */
const MAX_AUDIO_BYTES = 64 * 1024 * 1024;

const WAV_MAGIC_HEAD = 'RIFF';
const WAV_MAGIC_TAIL = 'WAVE';

function clampInt(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

export function createVideoMediaService({
  db,
  config,
  settings = null,
  files,
  videos,
  audit = null,
  ffmpegRunner = null,
  scratchRoot = os.tmpdir(),
} = {}) {
  const tool = ffmpegRunner ?? createFfmpegRunner({ timeoutMs: config?.video?.toolTimeoutMs ?? 30_000 });

  function toolsEnabled() {
    const v = settings?.bool?.('video.tools_enabled');
    return v === null || v === undefined ? false : Boolean(v);
  }

  /**
   * Le binaire n'est jamais supposé « sans doute » : avec un runner injecté (tests) on ne touche
   * pas au système de fichiers ; en production il faut un exécutable résolu, sinon refus nommé.
   */
  function resolveBin() {
    const raw = config?.video?.ffmpegPath ?? 'ffmpeg';
    if (ffmpegRunner) return binaryNameShape(raw) ?? raw;
    return safeBinaryPath(raw);
  }

  function limits() {
    const num = (key, def) => {
      const v = settings?.number?.(key);
      return Number.isFinite(v) ? v : def;
    };
    return {
      enabled: toolsEnabled(),
      width: clampInt(num('video.thumbnail_width', 320), 32, 1920, 320),
      atMs: clampInt(num('video.thumbnail_at_ms', 1000), 0, 86_400_000, 1000),
      maxOutBytes: clampInt(num('video.thumbnail_max_kb', 512), 8, 65_536, 512) * 1024,
      audioMaxSeconds: clampInt(num('video.audio_max_seconds', 300), 1, 3600, 300),
      timeoutMs: tool.timeout,
    };
  }

  /**
   * Paramètres de la tâche, relus depuis `input_json` puis **re-bornés ici** sans confiance : la
   * file a pu être remplie par un autre code, ou une autre version. Le décodeur ne reçoit que des
   * entiers dans leurs bornes, et un format parmi deux.
   */
  function jobInput(source) {
    let raw = source?.input_json ?? source?.input ?? null;
    // Idempotence : `deriveForJob` normalise une fois, puis passe l'objet au format interne aux
    // deux exécuteurs. Sans cette branche, un appel direct `thumbnail({ input: { width: 640 } })`
    // perdait silencieusement le paramètre et retombait sur le réglage — un défaut que l'on ne voit
    // que dans le résultat, jamais dans une erreur.
    const ALREADY = ['atMs', 'width', 'maxSeconds', 'maxKb', 'format'];
    if (raw == null && source && typeof source === 'object' && !Array.isArray(source) && ALREADY.some((k) => source[k] !== undefined)) {
      raw = source;
    }
    if (typeof raw === 'string') {
      try {
        raw = JSON.parse(raw);
      } catch {
        raw = null;
      }
    }
    const lim = limits();
    const src = raw && typeof raw === 'object' ? raw : {};
    return {
      atMs: clampInt(src.atMs, 0, 86_400_000, lim.atMs),
      width: clampInt(src.width, 32, 1920, lim.width),
      maxSeconds: clampInt(src.maxSeconds, 1, 3600, lim.audioMaxSeconds),
      maxOutBytes: clampInt(src.maxKb, 8, 65_536, Math.round(lim.maxOutBytes / 1024)) * 1024,
      format: src.format === 'wav' ? 'wav' : 'png',
    };
  }

  /** Aiguillage du worker : la tâche `thumbnail` porte son format dans son `input`. */
  function deriveForJob(job) {
    const videoId = job?.video_id ?? job?.videoId;
    if (!Number.isInteger(Number(videoId))) throw badRequest('Tâche sans vidéo cible.');
    const input = jobInput(job);
    return input.format === 'wav' ? audio({ videoId, input }) : thumbnail({ videoId, input });
  }

  /**
   * Le porteur du droit est le propriétaire de la vidéo, vérifié par la portée du dépôt : le worker
   * n'a pas de session, donc pas de « req.user » — l'identité vient de la ligne et doit la traverser.
   */
  function scopedAsset({ videoId }) {
    const ownerId = videoOwner(videoId);
    // Absent ou sans propriétaire : même réponse qu'un média hors de portée. Un 400 bavard dirait
    // à un attaquant quels identifiants existent dans la table.
    if (ownerId == null) throw notFound('Vidéo introuvable.');
    return videos.scopedRow({ id: Number(videoId), actor: { id: Number(ownerId) }, scopeAll: false });
  }

  function videoOwner(videoId) {
    const id = Number(videoId);
    if (!Number.isInteger(id) || id <= 0) return null;
    const row = db.get(`SELECT owner_id FROM video_assets WHERE id = ?`, [id]);
    return row?.owner_id ?? null;
  }

  function refuseUnavailable() {
    throw new AppError(503, TOOL_ERRORS.UNAVAILABLE, 'Aucun outil média n’est installé sur ce serveur : la production de vignettes et de pistes audio reste fermée.', {
      binaire: 'ffmpeg',
    });
  }

  /** `files.store` assainit le nom ; ceci n'est qu'un libellé lisible pour l'humain. */
  function sourceBaseName(fileRow) {
    return String(path.basename(String(fileRow?.original_name ?? 'video'))).replace(/\.[^.]+$/, '').slice(0, 60) || 'video';
  }

  function gate(videoId, action = null) {
    // Les refus de la porte (capacité fermée, outil absent, source refusée) sont journalisés sous le
    // même geste que les refus d'exécution : un opérateur doit pouvoir distinguer « la file n'avait
    // rien à faire » de « le worker a refusé, et pourquoi ». Les rejets génériques (404, 403) ne
    // passent pas ici : `recordRefusal` ne retient que les codes VIDEO_*.
    try {
      return gateInner(videoId);
    } catch (err) {
      if (action) recordRefusal(action, { id: Number(videoId) || null, owner_id: videoOwner(videoId) }, err);
      throw err;
    }
  }

  function gateInner(videoId) {
    if (!toolsEnabled()) {
      throw new AppError(409, TOOL_ERRORS.DISABLED, 'Le traitement des médias est fermé : activez le réglage video.tools_enabled.');
    }
    videos?.assertEnabled?.();
    const asset = scopedAsset({ videoId });
    assertReadyForRender(asset);
    const source = verifiedSource({ db, files, asset });
    const bin = resolveBin();
    if (!bin) refuseUnavailable();
    return { asset, ...source, bin };
  }

  function recordRefusal(action, asset, err) {
    if (!(err instanceof AppError) || !String(err.code ?? '').startsWith('VIDEO_')) return;
    // Un refus nommé est un événement : « l'outil a produit 40 Mo et on a jeté » doit se voir dans
    // le journal d'audit, pas disparaître avec le répertoire de travail.
    audit?.record?.({
      actor: { id: asset?.owner_id ?? null },
      action,
      category: 'agents',
      outcome: 'failure',
      targetType: 'video',
      targetId: asset?.id ?? null,
      severity: 'warning',
      detail: { code: err.code, reason: safeMessage(err) },
    });
  }

  /** Vignette PNG. `videoId` vient de la tâche, jamais d'une saisie libre. */
  function thumbnail({ videoId, input = null } = {}) {
    const { asset, fileRow, abs, bin } = gate(videoId, 'video.thumbnail.refused');
    const params = jobInput(input || {});
    const lim = limits();
    const atMs = params.atMs ?? lim.atMs;
    const width = params.width ?? lim.width;
    const maxOutBytes = params.maxOutBytes ?? lim.maxOutBytes;

    const scratch = makeScratch({ root: scratchRoot, label: 'ps-thumb' });
    const out = scratch.file('vignette.png');
    try {
      const res = tool.run({ bin, args: thumbnailArgs({ abs, out, atMs, width }), outPath: out, maxOutBytes });
      if (!res.ok) {
        throw new AppError(res.code === TOOL_ERRORS.UNAVAILABLE ? 503 : 422, res.code ?? TOOL_ERRORS.FAILED, `Vignette refusée : ${res.reason}`, res.detail ? { detail: res.detail } : undefined);
      }
      if (!isPng(res.buffer)) {
        throw new AppError(422, TOOL_ERRORS.OUTPUT_REFUSED, 'Sortie refusée : ce que l’outil a écrit n’est pas un PNG.');
      }
      const stored = files.store({
        owner: { id: asset.owner_id },
        originalName: `${sourceBaseName(fileRow)}-vignette.png`,
        mimeType: 'image/png',
        buffer: res.buffer,
        maxBytes: maxOutBytes,
        parentFileId: asset.file_id,
      });
      audit?.record?.({
        actor: { id: asset.owner_id },
        action: 'video.thumbnail.created',
        category: 'agents',
        outcome: 'success',
        targetType: 'video',
        targetId: asset.id,
        detail: { fileId: stored.file.id, bytes: res.bytes, width, atMs },
      });
      return {
        kind: 'thumbnail',
        format: 'png',
        fileId: stored.file.id,
        bytes: res.bytes,
        // Les paramètres réellement appliqués — pas ceux qui étaient demandés : un résultat qui
        // répète la demande sans dire ce qui a été écrêté serait une jauge fausse.
        width,
        atMs,
        maxBytes: maxOutBytes,
        duplicate: Boolean(stored.duplicate),
        videoId: asset.id,
      };
    } catch (err) {
      recordRefusal('video.thumbnail.refused', asset, err);
      throw err;
    } finally {
      scratch.dispose();
    }
  }

  /** Piste audio brute (WAV 16 kHz mono), même discipline : bornée, signée, rattachée, journalisée. */
  function audio({ videoId, input = null } = {}) {
    const { asset, fileRow, abs, bin } = gate(videoId, 'video.audio.refused');
    const params = jobInput(input || {});
    const lim = limits();
    const maxSeconds = params.maxSeconds ?? lim.audioMaxSeconds;
    // Le plafond de la piste n'est pas une marge au hasard : c'est ce que le profil demandé peut
    // physiquement produire (PCM 16 bits), plus l'en-tête. Une sortie qui dépasse ce chiffre n'est
    // pas un WAV trop long, c'est un outil qui écrit autre chose — et un millionième de gigaoctet
    // lu en mémoire dans un conteneur à 512 Mio est une panne, pas une nuance.
    const physical = 4096 + AUDIO_PROFILE.sampleRate * AUDIO_PROFILE.channels * 2 * maxSeconds;
    const cap = Math.min(MAX_AUDIO_BYTES, Math.max(physical, lim.maxOutBytes));

    const scratch = makeScratch({ root: scratchRoot, label: 'ps-audio' });
    const out = scratch.file('piste.wav');
    try {
      const res = tool.run({ bin, args: audioArgs({ abs, out, maxSeconds }), outPath: out, maxOutBytes: cap });
      if (!res.ok) {
        throw new AppError(res.code === TOOL_ERRORS.UNAVAILABLE ? 503 : 422, res.code ?? TOOL_ERRORS.FAILED, `Piste refusée : ${res.reason}`, res.detail ? { detail: res.detail } : undefined);
      }
      const head = res.buffer.subarray(0, 4).toString('latin1');
      const tail = res.buffer.subarray(8, 12).toString('latin1');
      if (head !== WAV_MAGIC_HEAD || tail !== WAV_MAGIC_TAIL) {
        throw new AppError(422, TOOL_ERRORS.OUTPUT_REFUSED, 'Sortie refusée : ce que l’outil a écrit n’est pas un WAV.');
      }
      const stored = files.store({
        owner: { id: asset.owner_id },
        originalName: `${sourceBaseName(fileRow)}-piste.wav`,
        mimeType: 'audio/wav',
        buffer: res.buffer,
        maxBytes: cap,
        parentFileId: asset.file_id,
      });
      audit?.record?.({
        actor: { id: asset.owner_id },
        action: 'video.audio.created',
        category: 'agents',
        outcome: 'success',
        targetType: 'video',
        targetId: asset.id,
        detail: { fileId: stored.file.id, bytes: res.bytes, seconds: maxSeconds },
      });
      return { kind: 'audio', format: 'wav', fileId: stored.file.id, bytes: res.bytes, seconds: maxSeconds, ...AUDIO_PROFILE, duplicate: Boolean(stored.duplicate), videoId: asset.id };
    } catch (err) {
      recordRefusal('video.audio.refused', asset, err);
      throw err;
    } finally {
      scratch.dispose();
    }
  }

  return { toolsEnabled, limits, jobInput, deriveForJob, thumbnail, audio, resolveBin, MEDIA_ERRORS };
}

export default createVideoMediaService;
