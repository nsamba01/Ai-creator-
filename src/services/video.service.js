/**
 * Agent Vidéo — phase A : ingestion et sondage d'en-tête.
 *
 * Ce qui est fait ici :
 *  - la vidéo doit d'abord passer par le pipeline de fichiers (extensions,
 *    MIME, signatures binaires, quota) : aucune voie latérale ;
 *  - le sondage lit des FENÊTRES (début, et fin si nécessaire) : jamais le
 *    fichier n'est chargé en entier ;
 *  - `ffprobe` n'est jamais requis : s'il est présent et autorisé, ses valeurs
 *    complètent le sondage ; sinon on reste sur l'analyse d'en-tête ;
 *  - aucune commande n'est construite à partir d'une entrée utilisateur : le
 *    seul argument variable est un chemin absolu stocké par nos soins ;
 *  - les métadonnées aberrantes (durée hors limite, dimensions impossibles)
 *    mettent la ressource en quarantaine plutôt que de la propager.
 *
 * Ce qui n'est PAS fait (phase B, cf. docs/VIDEO-AGENT.md) : transcodage,
 * vignettes, transcription, lecture en continu, collecte par URL.
 */
import fs from 'node:fs';
// lint-allow: exécution bornée d'un binaire externe, sans shell, arguments figés,
// environnement vidé, délai dur — et uniquement si l'opérateur l'autorise.
import { spawnSync } from 'node:child_process';
import { AppError, badRequest, forbidden, notFound, tooLarge } from '../utils/errors.js';
import { probeVideoWindows, sniffContainer } from './video-probe.js';
import { logger } from '../utils/logger.js';
import { createVideoRepository } from '../repositories/videos.repo.js';
import { boundedJson } from '../utils/json-limit.js';

export const VIDEO_EXTENSIONS = new Set(['.mp4', '.m4v', '.mov', '.mkv', '.webm', '.avi']);

export const VIDEO_ERRORS = {
  FEATURE_DISABLED: 'VIDEO_FEATURE_DISABLED',
  NOT_A_VIDEO: 'VIDEO_NOT_A_VIDEO',
  UNSUPPORTED_CONTAINER: 'VIDEO_UNSUPPORTED_CONTAINER',
  PROBE_FAILED: 'VIDEO_PROBE_FAILED',
  HEADER_INCOMPLETE: 'VIDEO_HEADER_INCOMPLETE',
  DURATION_EXCEEDED: 'VIDEO_DURATION_EXCEEDED',
  DIMENSIONS_INVALID: 'VIDEO_DIMENSIONS_INVALID',
  QUARANTINED: 'VIDEO_QUARANTINED',
  URL_NOT_IMPLEMENTED: 'VIDEO_URL_NOT_IMPLEMENTED',
};

/**
 * Chemin de binaire accepté : nom simple résolu dans PATH, ou chemin absolu — sans
 * métacaractère, sans traversée, et **uniquement si le fichier existe et s'exécute**.
 * Un nom non résolu renvoie null : le serveur n'annonce pas une capacité qu'il n'a pas.
 */
/** Forme acceptable pour un nom de binaire : ni espace, ni `$`, ni `;`, ni traversée. */
export function binaryNameShape(value) {
  const raw = String(value ?? 'ffprobe').trim();
  if (!raw || raw.length > 256) return null;
  if (!/^[A-Za-z0-9._/-]+$/.test(raw)) return null;
  if (raw.includes('..') || (raw.includes('/') && !raw.startsWith('/'))) return null;
  return raw;
}

export function safeBinaryPath(value) {
  const raw = binaryNameShape(value);
  if (!raw) return null;
  const candidates = raw.startsWith('/')
    ? [raw]
    : String(process.env.PATH ?? '')
        .split(':')
        .filter((d) => d.startsWith('/'))
        .map((d) => `${d.replace(/\/$/, '')}/${raw}`);
  for (const cand of candidates) {
    if (cand.length > 256) continue;
    try {
      const st = fs.statSync(cand);
      if (!st.isFile() || !(st.mode & 0o111)) continue;
      fs.accessSync(cand, fs.constants.X_OK);
      return cand;
    } catch {
      continue; // absent, non lisible, non exécutable : on passe au répertoire suivant
    }
  }
  return null;
}

/** Exécute ffprobe avec une ligne de commande figée. Injecté dans les tests. */
export function createFfprobeRunner({ timeoutMs = 10_000 } = {}) {
  return function run(bin, args) {
    // lint-allow: pas de shell, args en liste, délai dur, sortie bornée, aucun
    // argument issu de la saisie utilisateur (chemin absolu interne uniquement).
    const res = spawnSync(bin, args, {
      encoding: 'utf8',
      timeout: Math.max(250, Math.min(timeoutMs, 60_000)),
      maxBuffer: 1024 * 1024,
      env: { PATH: '/usr/local/bin:/usr/bin:/bin' },
    });
    if (res.error) return { ok: false, reason: res.error.code === 'ENOENT' ? 'binaire absent' : 'exécution impossible' };
    if (res.status !== 0) return { ok: false, reason: `ffprobe a répondu ${res.status}` };
    if (!res.stdout || res.stdout.length > 1024 * 1024) return { ok: false, reason: 'sortie illisible' };
    try {
      return { ok: true, json: JSON.parse(res.stdout) };
    } catch {
      return { ok: false, reason: 'sortie non JSON' };
    }
  };
}

/** Convertit la sortie ffprobe en champ de sondage (valeurs bornées). */
export function fromFfprobe(json) {
  const format = json?.format ?? {};
  const streams = Array.isArray(json?.streams) ? json.streams.slice(0, 32) : [];
  const video = streams.find((s) => s.codec_type === 'video' || s.video) ?? null;
  const parseRate = (v) => {
    const [a, b] = String(v ?? '').split('/');
    const num = Number(a);
    const den = Number(b ?? 1);
    if (!Number.isFinite(num) || !Number.isFinite(den) || den <= 0 || num <= 0) return null;
    const fps = num / den;
    return fps > 0 && fps <= 1000 ? Math.round(fps * 1000) / 1000 : null;
  };
  const durationMs = Number.isFinite(Number(format.duration)) ? Math.round(Number(format.duration) * 1000) : null;
  const streamsOut = streams.map((s) => ({
    type: s.codec_type ?? (s.width && s.height ? 'video' : 'unknown'),
    codec: typeof s.codec_name === 'string' ? s.codec_name.slice(0, 24) : null,
    width: positive(s.width),
    height: positive(s.height),
    fps: s.codec_type === 'video' ? parseRate(s.avg_frame_rate) ?? parseRate(s.r_frame_rate) : null,
    durationMs: Number.isFinite(Number(s.duration)) ? Math.round(Number(s.duration) * 1000) : null,
    name: typeof s.tags?.handler_name === 'string' ? s.tags.handler_name.slice(0, 40) : null,
  }));
  return {
    container: typeof format.format_name === 'string' ? format.format_name.split(',')[0].slice(0, 24) : null,
    brand: typeof format.brand === 'string' ? format.brand.slice(0, 24) : null,
    codec: typeof video?.codec_name === 'string' ? video.codec_name.slice(0, 24) : null,
    durationMs,
    width: positive(video?.width),
    height: positive(video?.height),
    fps: parseRate(video?.avg_frame_rate) ?? parseRate(video?.r_frame_rate),
    bitrateBps: Number.isFinite(Number(format.bit_rate)) && Number(format.bit_rate) > 0 ? Math.round(Number(format.bit_rate)) : null,
    trackCount: streams.length,
    streams: streamsOut,
    parser: 'ffprobe',
    notes: [],
  };
}

/** `req.user.permissions` est un tableau ; un Set est accepté pour les tests. */
function holds(actor, permission) {
  const perms = actor?.permissions;
  if (Array.isArray(perms)) return perms.includes(permission);
  if (perms instanceof Set) return perms.has(permission);
  return false;
}

function positive(n) {
  const v = Number(n);
  if (!Number.isFinite(v) || v <= 0 || v > 65536) return null;
  return Math.round(v);
}

export function createVideoService({ db, config, audit, files, agents, settings, ffprobeRunner = null } = {}) {
  let jobsService = null;
  const repo = createVideoRepository(db);
  const runFfprobe = ffprobeRunner ?? createFfprobeRunner({ timeoutMs: config.video?.probeTimeoutMs ?? 10_000 });

  function limits() {
    const video = config.video ?? {};
    const maxBytes = Math.min(config.uploads?.maxBytes ?? video.maxBytes ?? 10 * 1024 * 1024, video.maxBytes ?? 10 * 1024 * 1024);
    const fromSettings = Number(settings?.number('video.max_duration_seconds', video.maxDurationMs / 1000 ?? 3600));
    const maxDurationMs = Math.min(video.maxDurationMs ?? 3_600_000, (Number.isFinite(fromSettings) && fromSettings > 0 ? fromSettings : 3600) * 1000);
    return { maxBytes, maxDurationMs, windowBytes: video.probeWindowBytes ?? 256 * 1024 };
  }

  /** L'interrupteur est une décision d'administrateur, pas un réglage d'API. */
  function enabled() {
    return Boolean(settings?.bool('video.enabled', false));
  }

  function assertEnabled() {
    if (!enabled()) {
      const err = new AppError(409, VIDEO_ERRORS.FEATURE_DISABLED, "L’ingestion vidéo est désactivée : activez le réglage « video.enabled » en Configuration.");
      throw err;
    }
  }

  function readWindows(abs, size, windowBytes) {
    const headLen = Math.max(0, Math.min(size, windowBytes));
    const head = Buffer.alloc(headLen);
    let tail = null;
    const fd = fs.openSync(abs, 'r');
    try {
      if (headLen > 0) fs.readSync(fd, head, 0, headLen, 0);
      if (size > windowBytes * 2) {
        const tailLen = Math.min(windowBytes, size - windowBytes);
        tail = Buffer.alloc(tailLen);
        fs.readSync(fd, tail, 0, tailLen, size - tailLen);
      }
    } finally {
      fs.closeSync(fd);
    }
    return { head, tail };
  }

  function probeFile(abs, size, { allowFfprobe = true } = {}) {
    const caps = limits();
    const { head, tail } = readWindows(abs, size, caps.windowBytes);
    const header = probeVideoWindows(head, tail, { maxDurationMs: caps.maxDurationMs, bytes: size });

    const canUseFfprobe = allowFfprobe && config.video?.useFfprobe !== false && Boolean(settings?.bool('video.use_ffprobe', true));
    let ff = null;
    let notes = [...(header.notes ?? [])];
    if (canUseFfprobe) {
      // Un exécuteur injecté (test, ou bac à sable maison) n'a pas de binaire à vérifier :
      // la forme du nom suffit, et c'est l'exécuteur qui répond de l'exécution.
      const bin = ffprobeRunner ? binaryNameShape(config.video?.ffprobePath) : safeBinaryPath(config.video?.ffprobePath);
      if (!bin) {
        notes.push(ffprobeRunner ? 'FFPROBE_PATH refusé (forme inattendue) : sondage sur en-tête uniquement' : 'ffprobe introuvable ou non exécutable sur ce serveur : sondage sur en-tête uniquement');
      } else {
        // Arguments figés ; le chemin est le nôtre, absolu, jamais celui du client.
        const res = runFfprobe(bin, ['-v', 'error', '-print_format', 'json', '-show_format', '-show_streams', '-i', abs]);
        if (res?.ok) ff = fromFfprobe(res.json);
        else notes.push(`ffprobe indisponible (${res?.reason ?? 'réponse inconnue'}) : repli sur l’analyse d’en-tête`);
      }
    }

    const merged = ff
      ? {
          ...header,
          ok: true,
          errorCode: null,
          container: ff.container ?? header.container,
          brand: ff.brand ?? header.brand,
          codec: ff.codec ?? header.codec,
          durationMs: ff.durationMs ?? header.durationMs,
          width: ff.width ?? header.width,
          height: ff.height ?? header.height,
          fps: ff.fps ?? header.fps,
          bitrateBps: ff.bitrateBps ?? header.bitrateBps,
          trackCount: ff.trackCount || header.trackCount,
          streams: ff.streams?.length ? ff.streams : header.streams ?? [],
          probeSource: header.ok ? 'header+ffprobe' : 'ffprobe',
          notes,
        }
      // Un refus motivé (durée, dimensions) reste un sondage d’en-têtes : le rapport a été
      // produit par ce lecteur, il faut que la colonne `probe_source` le dise.
      : { ...header, probeSource: header.parser ? 'header' : 'none', notes };

    // Bornes de cohérence : la durée venant de ffprobe doit aussi être vérifiée.
    if (merged.durationMs !== null && merged.durationMs > caps.maxDurationMs) {
      return {
        ...merged,
        ok: false,
        errorCode: VIDEO_ERRORS.DURATION_EXCEEDED,
        notes: [...notes, `durée ${Math.round(merged.durationMs / 1000)} s, limite ${Math.round(caps.maxDurationMs / 1000)} s`],
      };
    }
    if ((merged.width !== null && merged.width > 16384) || (merged.height !== null && merged.height > 16384)) {
      return { ...merged, ok: false, errorCode: VIDEO_ERRORS.DIMENSIONS_INVALID, notes: [...notes, 'dimensions hors bornes'] };
    }
    if (merged.width == null && header.container === 'mp4' && !merged.durationMs && !ff) {
      return { ...merged, ok: false, errorCode: VIDEO_ERRORS.HEADER_INCOMPLETE };
    }
    return merged;
  }

  function assertVideoFile(fileRow) {
    const ext = String(fileRow.extension ?? '').toLowerCase();
    if (fileRow.kind !== 'video' && !VIDEO_EXTENSIONS.has(ext)) {
      throw badRequest(`Ce fichier n’est pas une vidéo reconnue (${ext || 'extension inconnue'}).`, { code: VIDEO_ERRORS.NOT_A_VIDEO });
    }
    if (ext && !VIDEO_EXTENSIONS.has(ext)) {
      throw unsupported(VIDEO_ERRORS.UNSUPPORTED_CONTAINER, `Conteneur non pris en charge (${ext}).`);
    }
  }

  function register({ actor, fileId }) {
    assertEnabled();
    const id = Number(fileId);
    if (!Number.isInteger(id) || id <= 0) throw badRequest('Identifiant de fichier attendu.');
    const stored = db.get(`SELECT * FROM files WHERE id = ? AND deleted_at IS NULL`, [id]);
    if (!stored) throw notFound('Fichier introuvable.');
    const isOwner = stored.owner_id === actor.id;
    if (!isOwner && !holds(actor, 'videos:read:any') && !holds(actor, 'files:read:any')) {
      throw forbidden('Ce fichier appartient à un autre utilisateur.');
    }
    assertVideoFile(stored);

    const caps = limits();
    if (stored.size_bytes > caps.maxBytes) {
      throw tooLarge(`Vidéo trop volumineuse pour l’ingestion (limite ${Math.round((caps.maxBytes / 1048576) * 10) / 10} Mo).`);
    }

    const existing = repo.getByFileId(stored.id);
    if (existing) {
      // Déjà déclarée : on renvoie l'état courant, sans doubler la ligne ni les octets.
      audit?.record({ actor, action: audit.AUDIT?.VIDEO_REGISTERED ?? 'video.registered', category: 'agents', outcome: 'success', targetType: 'video', targetId: existing.id, detail: { fileId: stored.id, alreadyRegistered: true } });
      return { asset: rowToDto(repo.getById(existing.id)), created: false };
    }

    const task = agents?.create({
      title: `Sondage vidéo — ${stored.original_name}`.slice(0, 200),
      agentRole: 'video',
      priority: 'normal',
      description: 'Phase A : lecture des en-têtes de conteneur, puis sondage ffprobe si disponible. Aucun transcodage.',
      createdBy: actor.id,
    });

    const created = repo.createAsset({
      fileId: stored.id,
      ownerId: stored.owner_id,
      fileSize: stored.size_bytes,
      sha256: stored.sha256,
      taskId: task?.id ?? null,
    });

    // Mode « file » (réglage video.async_probe) : la requête ne sonde pas, elle met en file.
    // Le sondeur de 512 Kio est rapide, mais un ffprobe de 10 s dans une requête HTTP est
    // un déni de service offert ; l'administrateur choisit laquelle des deux voies il ouvre.
    if (jobsService && asyncMode()) {
      const queued = jobsService.enqueue({ actor, videoId: created.id, kind: 'probe' });
      audit?.record({ actor, action: 'video.job.queued', category: 'agents', outcome: 'success', targetType: 'video', targetId: created.id, detail: { fileId: stored.id, kind: 'probe', via: 'register' } });
      return { asset: rowToDto(repo.getById(created.id)), created: true, task: task ?? null, queued: true, job: queued.job };
    }

    const result = probeAndPersist(created, stored, { actor, taskId: task?.id ?? null });
    audit?.record({ actor, action: audit.AUDIT?.VIDEO_REGISTERED ?? 'video.registered', category: 'agents', outcome: 'success', targetType: 'video', targetId: result.asset.id, detail: { fileId: stored.id, taskId: task?.id ?? null } });
    return { asset: result.asset, created: true, task: task ?? null, analysis: result.analysis, queued: false };
  }

  /** Exécution d'un job de sondage : mêmes écritures que le chemin synchrone, acteur = le propriétaire. */
  function probeForJob({ videoId }) {
    const row = repo.getById(Number(videoId));
    if (!row) throw notFound('Vidéo introuvable.');
    const fileRow = db.get(`SELECT * FROM files WHERE id = ? AND deleted_at IS NULL`, [row.file_id]);
    if (!fileRow) throw notFound('Fichier source introuvable.');
    db.run(`UPDATE video_assets SET status = 'probing', updated_at = ? WHERE id = ?`, [new Date().toISOString(), row.id]);
    return probeAndPersist(repo.getById(row.id), fileRow, { actor: null, taskId: row.task_id ?? null });
  }

  /** Late binding de la file : le service de jobs a besoin de celui-ci, on évite l'import circulaire. */
  function attachJobs(service) {
    jobsService = service;
  }

  function asyncMode() {
    const v = settings?.bool?.('video.async_probe');
    return v === null || v === undefined ? false : Boolean(v);
  }

  function probeAndPersist(assetRow, fileRow, { actor, taskId = null }) {
    const started = Date.now();
    let probe = null;
    let error = null;
    try {
      const abs = fileRow ? files.resolveStored(fileRow.relative_path) : files.readAbsolute(assetRow.file_id).abs;
      const size = fileRow?.size_bytes ?? assetRow.file_size_bytes ?? 0;
      probe = probeFile(abs, size);
    } catch (err) {
      if (err instanceof AppError && (err.status === 404 || err.code === 'BAD_PATH')) throw err;
      error = err?.message ?? 'sondage impossible';
      probe = { ok: false, errorCode: VIDEO_ERRORS.PROBE_FAILED, container: null, notes: ['lecture du fichier impossible'], streams: [], probeSource: 'none' };
    }

    const quarantineOnFailure = config.video?.quarantineOnFailure !== false;
    const status = probe.ok ? 'ready' : quarantineOnFailure ? 'quarantined' : 'failed';
    const meta = {
      container: probe.container,
      brand: probe.brand ?? null,
      compatible: probe.compatible ?? [],
      codec: probe.codec ?? null,
      durationMs: probe.durationMs ?? null,
      width: probe.width ?? null,
      height: probe.height ?? null,
      fps: probe.fps ?? null,
      bitrateBps: probe.bitrateBps ?? null,
      trackCount: probe.trackCount ?? 0,
      fragmented: Boolean(probe.fragmented),
      truncated: Boolean(probe.truncated),
      parser: probe.parser ?? null,
      probeSource: probe.probeSource ?? probe.probeSourceName ?? (probe.parser === 'ffprobe' ? 'ffprobe' : 'header'),
      streams: probe.streams ?? [],
      notes: probe.notes ?? [],
      errorCode: probe.errorCode ?? null,
    };
    const updated = repo.applyProbe(assetRow.id, {
      container: probe.container,
      brand: probe.brand,
      codec: probe.codec,
      durationMs: probe.durationMs,
      width: probe.width,
      height: probe.height,
      fps: probe.fps,
      bitrateBps: probe.bitrateBps,
      trackCount: probe.trackCount,
      parser: probe.parser,
      probeSource: meta.probeSource,
      status,
      errorCode: probe.errorCode ?? (error ? VIDEO_ERRORS.PROBE_FAILED : null),
      notes: (probe.notes ?? []).join(' · ').slice(0, 1000),
      metaJson: boundedJson(meta, 16_000),
    });
    const analysis = repo.recordAnalysis({
      videoId: assetRow.id,
      kind: 'probe',
      status: probe.ok ? 'ok' : 'failed',
      model: probe.parser === 'ffprobe' ? 'ffprobe' : `en-têtes:${probe.parser ?? 'inconnu'}`,
      result: boundedJson(meta, 30_000),
      error: probe.ok ? null : (probe.errorCode ?? VIDEO_ERRORS.PROBE_FAILED),
      costMs: Date.now() - started,
    });
    if (taskId && agents) {
      try {
        agents.update(taskId, { status: probe.ok ? 'done' : 'failed', resultSummary: `sondage ${probe.ok ? 'réussi' : 'refusé'} — ${probe.container ?? 'conteneur inconnu'}, ${probe.width ?? '?'}×${probe.height ?? '?'} px, ${Math.round((probe.durationMs ?? 0) / 1000)} s`, priority: 'normal' }, { actor });
      } catch (err) {
        logger.warn('mise à jour de tâche de sondage impossible', { taskId, error: err.message });
      }
    }
    audit?.record({
      actor,
      action: probe.ok ? (audit.AUDIT?.VIDEO_PROBED ?? 'video.probed') : (audit.AUDIT?.VIDEO_QUARANTINED ?? 'video.quarantined'),
      category: 'agents',
      outcome: probe.ok ? 'success' : 'blocked',
      severity: probe.ok ? 'info' : 'warning',
      targetType: 'video',
      targetId: assetRow.id,
      detail: {
        fileId: assetRow.file_id,
        container: probe.container,
        status,
        errorCode: probe.errorCode ?? null,
        bytes: assetRow.file_size_bytes,
      },
    });
    return { asset: rowToDto(updated), analysis: analysisToDto(analysis), meta };
  }

  function reprobe({ id, actor }) {
    assertEnabled();
    const row = repo.getById(id) ?? scopedFail(id, actor);
    if (row.status === 'quarantined' && !holds(actor, 'videos:process')) {
      throw forbidden('Vidéo en quarantaine : seule une autorisation « videos:process » peut la relancer.');
    }
    const fileRow = db.get(`SELECT * FROM files WHERE id = ?`, [row.file_id]);
    if (!fileRow) throw notFound('Fichier source introuvable.');
    const { asset, analysis } = probeAndPersist(row, fileRow, { actor, taskId: row.task_id ?? null });
    return { asset, analyses: [analysis] };
  }

  function setQuarantine({ id, actor, quarantined }) {
    const row = repo.getById(id) ?? scopedFail(id, actor);
    // Levée = « on refait confiance au rapport », pas « on fait semblant » : une vidéo jamais
    // sondée repasse en `pending` (et devra être sondée) au lieu d'être déclarée prête.
    const neverProbed = !quarantined && (row.probe_source ?? 'none') === 'none';
    const next = quarantined ? 'quarantined' : neverProbed ? 'pending' : 'ready';
    const updated = repo.setStatus(row.id, {
      status: next,
      errorCode: quarantined ? VIDEO_ERRORS.QUARANTINED : null,
      notes: quarantined
        ? 'quarantaine décidée par un administrateur'
        : neverProbed
          ? 'quarantaine levée : aucun sondage enregistré, à re-sonder avant usage'
          : 'quarantaine levée après revue',
    });
    audit?.record({
      actor,
      action: quarantined ? (audit.AUDIT?.VIDEO_QUARANTINED ?? 'video.quarantined') : (audit.AUDIT?.VIDEO_RELEASED ?? 'video.released'),
      category: 'agents',
      outcome: 'success',
      severity: 'notice',
      targetType: 'video',
      targetId: row.id,
      detail: { fileId: row.file_id },
    });
    return rowToDto(updated);
  }

  function scopedFail(id, actor) {
    const row = db.get(`SELECT * FROM video_assets WHERE id = ? AND deleted_at IS NULL`, [Number(id)]);
    if (!row) throw notFound('Vidéo introuvable.');
    if (row.owner_id !== actor.id && !holds(actor, 'videos:read:any')) throw forbidden('Vidéo d’un autre utilisateur.');
    return row;
  }

  /**
   * Ligne d'actif **après** contrôle de portée. Un seul chemin pour la lecture du rapport et
   * pour la lecture des octets : deux portées différentes selon la route seraient une faille
   * déguisée en détail d'implémentation.
   */
  function scopedRow({ id, actor, scopeAll = false }) {
    const row = repo.getById(Number(id)) ?? null;
    if (!row) throw notFound('Vidéo introuvable.');
    if (!scopeAll && row.owner_id !== actor?.id && !holds(actor, 'videos:read:any')) throw forbidden('Vidéo d’un autre utilisateur.');
    return row;
  }

  function get({ id, actor, scopeAll = false }) {
    const row = scopedRow({ id, actor, scopeAll });
    const fileRow = db.get(`SELECT id, original_name, mime_type, extension, size_bytes, deleted_at FROM files WHERE id = ?`, [row.file_id]);
    return { asset: rowToDto(row), file: fileRow ? { id: fileRow.id, name: fileRow.original_name, mime: fileRow.mime_type, extension: fileRow.extension, bytes: fileRow.size_bytes, deleted: Boolean(fileRow.deleted_at) } : null, analyses: repo.latestAnalyses(row.id).map(analysisToDto) };
  }

  function list({ actor, scopeAll = false, status = '', limit = 25, offset = 0, q = '' } = {}) {
    const { total, rows } = repo.list({
      ownerId: scopeAll ? null : actor.id,
      status: ['pending', 'probing', 'ready', 'failed', 'quarantined'].includes(status) ? status : '',
      limit,
      offset,
      q: String(q ?? '').slice(0, 60),
    });
    return { total, items: rows.map((r) => ({ ...rowToDto(r), fileName: r.original_name, ownerName: r.owner_name, fileDeleted: Boolean(r.file_deleted_at) })) };
  }

  function stats({ actor = null, scopeAll = false } = {}) {
    const s = repo.stats({ ownerId: scopeAll ? null : actor?.id ?? null });
    const ffprobeUsable = ffprobeRunner ? Boolean(binaryNameShape(config.video?.ffprobePath)) : Boolean(safeBinaryPath(config.video?.ffprobePath));
    return { ...s, enabled: enabled(), ffprobeConfigured: ffprobeUsable, limits: { maxBytes: limits().maxBytes, maxDurationMs: limits().maxDurationMs, windowBytes: limits().windowBytes } };
  }

  function onFileRemoved(fileId) {
    return repo.softDeleteByFileId(fileId, new Date().toISOString());
  }

  return { repo, register, reprobe, get, list, setQuarantine, stats, limits, enabled, assertEnabled, onFileRemoved, probeFile, scopedRow, scopedFail, attachJobs, asyncMode, probeForJob, VIDEO_EXTENSIONS, VIDEO_ERRORS };
}

function unsupported(code, message) {
  const err = new AppError(415, code, message);
  throw err;
}

export function rowToDto(row) {
  return {
    id: row.id,
    fileId: row.file_id,
    ownerId: row.owner_id,
    container: row.container,
    brand: row.brand,
    codec: row.codec,
    durationMs: row.duration_ms,
    width: row.width,
    height: row.height,
    fps: row.fps,
    bitrateBps: row.bitrate_bps,
    trackCount: row.track_count,
    parser: row.parser,
    probeSource: row.probe_source,
    status: row.status,
    errorCode: row.error_code,
    notes: row.notes ? String(row.notes).split(' · ') : [],
    sizeBytes: row.file_size_bytes,
    sha256: row.sha256 ? String(row.sha256).slice(0, 16) : null,
    taskId: row.task_id,
    probedAt: row.probed_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    meta: safeJson(row.meta_json),
  };
}

function analysisToDto(row) {
  return {
    id: row.id,
    kind: row.kind,
    status: row.status,
    model: row.model,
    result: safeJson(row.result_json),
    error: row.error,
    costMs: row.cost_ms,
    createdAt: row.created_at,
  };
}

function safeJson(s) {
  if (!s) return null;
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}

export default createVideoService;
