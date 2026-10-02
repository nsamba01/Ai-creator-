/**
 * File d'exécution de l'agent vidéo (phase B).
 *
 * Deux objets :
 *  - `createVideoJobService` : la façade HTTP (mettre en file, consulter, annuler, relancer),
 *    avec la portée et le garde-fou d'interruption ;
 *  - `createVideoJobRunner` : la boucle qui exécute — **dans un processus séparé**
 *    (`npm run worker`), jamais dans le serveur web. Le serveur n'appelle `tick()` que si on
 *    le lui demande explicitement (tests, mode mono-processus assumé).
 *
 * Le message d'erreur d'un job ne remonte jamais brut : un `ENOENT` contient le chemin de
 * stockage, et la liste des tâches est lisible par un compte standard sur SES vidéos.
 */
import { createVideoJobsRepository } from '../repositories/video-jobs.repo.js';
import { AppError, badRequest, forbidden, notFound } from '../utils/errors.js';
import { redact } from '../utils/logger.js';
import { VIDEO_JOB_KINDS, VIDEO_JOB_STATUSES } from '../repositories/video-jobs.repo.js';

const JOB_ERRORS = {
  BUSY: 'VIDEO_JOB_BUSY',
  NOT_ALLOWED: 'VIDEO_JOB_NOT_ALLOWED',
  TOOL_UNAVAILABLE: 'VIDEO_TOOL_UNAVAILABLE',
  LEASE_LOST: 'VIDEO_LEASE_LOST',
  CANCELLED: 'VIDEO_CANCELLED',
};

/** Chemin, URL file://, ou fragment de pile : rien de tout cela ne sort du processus. */
function safeMessage(err) {
  const raw = String(err?.message ?? err ?? 'erreur inconnue').replace(/[\u0000-\u0008]/g, ' ');
  const stripped = redact(raw)
    .replace(/(?:file:\/\/)?(?:\/[\w.\-]+)+/g, '[chemin masqué]')
    .replace(/[A-Za-z]:\\(?:[\w.\-\\]+)+/g, '[chemin masqué]')
    .replace(/\s+/g, ' ')
    .trim();
  return stripped.slice(0, 300) || 'erreur non nommée';
}

export function createVideoJobService({ db, config, settings = null, audit = null, videos = null, jobs = null } = {}) {
  const repo = jobs ?? createVideoJobsRepository(db);

  const holds = (actor, perm) => Array.isArray(actor?.permissions) ? actor.permissions.includes(perm) : Boolean(actor?.permissions?.has?.(perm));

  function limits() {
    const num = (key, def) => {
      const v = settings?.number?.(key);
      return Number.isFinite(v) ? v : def;
    };
    return {
      leaseMs: Math.max(2000, num('video.lease_seconds', 120) * 1000),
      maxAttempts: Math.max(1, Math.min(16, num('video.max_attempts', 3))),
      backoffMs: Math.max(0, num('video.backoff_seconds', 2) * 1000),
      concurrency: Math.max(1, Math.min(8, num('video.worker_concurrency', 1))),
    };
  }

  function assetFor(videoId, actor, { write = false } = {}) {
    const asset = videos?.repo?.getById?.(videoId) ?? null;
    if (!asset) throw notFound('Vidéo introuvable.');
    const owner = asset.owner_id === actor?.id;
    if (!owner && !holds(actor, write ? 'videos:process' : 'videos:read:any')) {
      throw forbidden('Cette vidéo appartient à un autre utilisateur.');
    }
    return asset;
  }

  /** Mettre en file. Les kinds lourds (montage, transcription, vignette, modération) sont un acte d'administration. */
  function enqueue({ actor, videoId, kind = 'probe', input = null }) {
    if (!VIDEO_JOB_KINDS.includes(kind)) throw badRequest(`Type de tâche inconnu (${kind}).`);
    if (kind !== 'probe' && !holds(actor, 'videos:process')) {
      throw forbidden(`Un job « ${kind} » demande la permission videos:process.`);
    }
    videos?.assertEnabled?.();
    const asset = assetFor(videoId, actor, { write: kind !== 'probe' });
    if (asset.status === 'quarantined' && !holds(actor, 'videos:process')) {
      throw forbidden('Vidéo en quarantaine : la relance demande videos:process.');
    }
    const l = limits();
    const row = repo.enqueue({
      videoId: asset.id,
      fileId: asset.file_id,
      ownerId: asset.owner_id,
      kind,
      input,
      maxAttempts: l.maxAttempts,
      priority: kind === 'probe' ? 6 : 4,
      jobTaskId: asset.task_id ?? null,
    });
    audit?.record?.({
      actor,
      action: 'video.job.queued',
      category: 'agents',
      outcome: 'success',
      targetType: 'video_job',
      targetId: row.id,
      detail: { videoId: asset.id, kind, attempts: row.attempts, maxAttempts: row.max_attempts },
    });
    return { job: rowToDto(row), limits: l };
  }

  function listFor({ actor, videoId = null, status = '', scopeAll = false, limit = 50, offset = 0 } = {}) {
    // Un `videoId` non numérique (saisie, bot) ne doit pas vider la liste ni lever : il est ignoré.
    const onlyVideo = videoId == null || !Number.isFinite(Number(videoId)) ? null : Number(videoId);
    const out = repo.list({
      videoId: onlyVideo,
      status,
      ownerId: scopeAll ? null : actor?.id ?? null,
      limit,
      offset,
    });
    return { items: out.items.map(rowToDto), total: out.total, limit: out.limit ?? limit, offset: out.offset ?? offset };
  }

  function get({ actor, id, scopeAll = false }) {
    const row = repo.getById(Number(id));
    if (!row) throw notFound('Tâche introuvable.');
    if (!scopeAll && row.owner_id !== actor?.id && !holds(actor, 'videos:manage-jobs')) {
      throw forbidden('Cette tâche appartient à un autre utilisateur.');
    }
    return rowToDto(row);
  }

  function act({ actor, id, action }) {
    const row = repo.getById(Number(id));
    if (!row) throw notFound('Tâche introuvable.');
    if (!holds(actor, 'videos:manage-jobs') && row.owner_id !== actor?.id) {
      throw forbidden('Gestion de tâche réservée à son propriétaire ou à un administrateur.');
    }
    if (action === 'cancel') {
      if (row.status === 'succeeded') throw new AppError(409, JOB_ERRORS.BUSY, 'Une tâche réussie ne s’annule pas : relancez-la si besoin.');
      const out = repo.cancel({ id: row.id });
      audit?.record?.({ actor, action: 'video.job.cancelled', category: 'agents', outcome: 'success', targetType: 'video_job', targetId: row.id, detail: { kind: row.kind } });
      return { job: rowToDto(out) };
    }
    if (action === 'retry') {
      if (row.status === 'running') throw new AppError(409, JOB_ERRORS.BUSY, 'La tâche est en cours : annulez-la d’abord.');
      const out = repo.requeue({ id: row.id });
      audit?.record?.({ actor, action: 'video.job.requeued', category: 'agents', outcome: 'success', targetType: 'video_job', targetId: row.id, detail: { kind: row.kind } });
      return { job: rowToDto(out) };
    }
    throw badRequest(`Action inconnue (${action}).`);
  }

  function stats({ actor = null, scopeAll = false } = {}) {
    const s = repo.stats({ ownerId: scopeAll ? null : actor?.id ?? null });
    const byStatus = Object.fromEntries(VIDEO_JOB_STATUSES.map((k) => [k, 0]));
    let bytes = 0;
    for (const row of s.byStatus) {
      byStatus[row.status] = row.n;
      bytes += row.bytes ?? 0;
    }
    return { ...byStatus, bytes, queuedOldest: s.queuedOldest, expiredLeases: s.expiredLeases, limits: limits() };
  }

  /**
   * Ramassage des bails perdus, et purge optionnelle des tâches terminées plus anciennes qu'une date.
   * L'appel passe par le service (et non par `repo`) pour que l'acte d'administration soit journalisé :
   * effacer l'historique d'exécution sans trace serait précisément ce qu'un audit doit empêcher.
   */
  function reap({ actor = null, purgeBefore = null, kinds = null } = {}) {
    const out = repo.reapExpired({ requeueAfter: new Date().toISOString() });
    let purged = 0;
    if (purgeBefore != null && purgeBefore !== '') {
      const stamp = new Date(String(purgeBefore));
      if (Number.isNaN(stamp.getTime())) throw badRequest('purgeBefore attendu en date ISO (ex. 2026-01-01T00:00:00.000Z).');
      purged = repo.purgeFinished({ before: stamp.toISOString(), ...(kinds ? { kinds } : {}) }).removed;
    }
    audit?.record?.({
      actor,
      action: 'video.jobs.reap',
      category: 'agents',
      outcome: 'success',
      targetType: 'video_jobs',
      targetId: null,
      detail: { examined: out.examined, requeued: out.requeued, failed: out.failed, purged },
    });
    return { ...out, purged };
  }

  return { repo, enqueue, listFor, get, act, stats, limits, reap, JOB_ERRORS };
}

/**
 * Boucle d'exécution. `tick()` est appelé par le processus worker (ou par un test) ; il
 * réclame une tâche, lui délègue le travail, prolonge son bail, puis écrit le résultat.
 */
export function createVideoJobRunner({ service, videos, db, workerId = `worker-${process.pid}`, handlers = {}, onOutcome = null, kinds = null } = {}) {
  let timer = null;
  let stopping = false;
  const repo = service.repo;
  // Un worker ne prélève que ce qu’il sait exécuter ; sans liste explicite il prend tout, et un kind
  // non pris en charge est alors refusé nommément (VIDEO_TOOL_UNAVAILABLE) au lieu de rester vide.
  const claimKinds = Array.isArray(kinds) && kinds.length ? [...new Set(kinds.filter(Boolean).map(String))] : null;

  function leaseMs() {
    return service.limits().leaseMs;
  }

  async function tick() {
    const l = service.limits();
    const reaped = repo.reapExpired({ requeueAfter: new Date().toISOString() });
    const claimed = [];
    for (let i = 0; i < Math.max(1, l.concurrency); i += 1) {
      const job = repo.claim({ worker: workerId, leaseMs: l.leaseMs, kinds: claimKinds });
      if (!job) break;
      claimed.push(await runOne(job, l));
    }
    return { reaped, claimed, idle: claimed.length === 0 };
  }

  async function runOne(job, l) {
    const handler = handlers[job.kind];
    const started = Date.now();
    if (!handler) {
      const out = repo.finish({
        id: job.id,
        worker: workerId,
        ok: false,
        errorCode: JOB_ERRORS.TOOL_UNAVAILABLE,
        errorMessage: `aucun exécuteur enregistré pour le kind « ${job.kind} »`,
        // Repasser en file avec le backoff, pas immédiatement : sinon ce worker rejoue la même tâche
        // refusée en boucle serrée et affame le reste de la file.
        requeueAfter: new Date(Date.now() + Math.max(1000, l.backoffMs)).toISOString(),
      });
      onOutcome?.({ job, ok: false, errorCode: JOB_ERRORS.TOOL_UNAVAILABLE, lost: out?.lost });
      return { id: job.id, kind: job.kind, ok: false, errorCode: JOB_ERRORS.TOOL_UNAVAILABLE, forced: true };
    }
    const ctx = {
      workerId,
      job,
      videos,
      db,
      heartbeat(progress) {
        repo.heartbeat({ id: job.id, worker: workerId, leaseMs: l.leaseMs, progress });
      },
    };
    try {
      const result = await handler(job, ctx);
      const out = repo.finish({ id: job.id, worker: workerId, ok: true, result: result ?? null });
      if (out?.lost) {
        onOutcome?.({ job, ok: false, errorCode: JOB_ERRORS.LEASE_LOST });
        return { id: job.id, kind: job.kind, ok: false, errorCode: JOB_ERRORS.LEASE_LOST };
      }
      onOutcome?.({ job, ok: true, ms: Date.now() - started });
      return { id: job.id, kind: job.kind, ok: true, ms: Date.now() - started };
    } catch (err) {
      const attempts = job.attempts ?? 1;
      const backoff = Math.min(3_600_000, l.backoffMs * 2 ** Math.max(0, attempts - 1));
      const runAfter = backoff > 0 ? new Date(Date.now() + backoff).toISOString() : null;
      const out = repo.finish({
        id: job.id,
        worker: workerId,
        ok: false,
        errorCode: err instanceof AppError ? err.code : 'VIDEO_JOB_FAILED',
        errorMessage: safeMessage(err),
        requeueAfter: runAfter,
      });
      onOutcome?.({ job, ok: false, errorCode: err?.code ?? 'VIDEO_JOB_FAILED', retrying: Boolean(out?.retrying) });
      return { id: job.id, kind: job.kind, ok: false, retrying: Boolean(out?.retrying), errorCode: err?.code ?? 'VIDEO_JOB_FAILED' };
    }
  }

  /** Boucle autonome (processus worker). `once` = un seul tour, pour les tests. */
  function start({ pollMs = 1000, maxTicks = Infinity, onTick = null } = {}) {
    let ticks = 0;
    const loop = async () => {
      if (stopping) return;
      try {
        const out = await tick();
        onTick?.(out);
      } catch (err) {
        onTick?.({ error: safeMessage(err) });
      }
      ticks += 1;
      if (ticks >= maxTicks || stopping) return;
      timer = setTimeout(loop, Math.max(100, pollMs));
      timer.unref?.();
    };
    loop();
    return () => stop();
  }

  function stop() {
    stopping = true;
    if (timer) clearTimeout(timer);
    timer = null;
  }

  return { tick, start, stop, workerId };
}

function rowToDto(row) {
  if (!row) return null;
  return {
    id: row.id,
    videoId: row.video_id,
    fileId: row.file_id,
    kind: row.kind,
    status: row.status,
    attempts: row.attempts,
    maxAttempts: row.max_attempts,
    priority: row.priority,
    progress: row.progress ?? null,
    errorCode: row.error_code ?? null,
    error: row.error_message ?? null,
    runAfter: row.run_after ?? null,
    leaseExpiresAt: row.lease_expires_at ?? null,
    running: row.status === 'running' ? Boolean(row.locked_by) : false,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    startedAt: row.started_at ?? null,
    finishedAt: row.finished_at ?? null,
    result: safeParse(row.result_json),
    fileName: row.file_name ?? null,
  };
}

function safeParse(text) {
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return { unparsable: true };
  }
}

export { JOB_ERRORS as VIDEO_JOB_ERRORS };
