/**
 * Accès SQL de la file d'exécution vidéo (phase B).
 *
 * Trois invariants, tous prouvés par les tests :
 *  1. **un seul preneur** : le claim est une transition d'état conditionnelle
 *     (`WHERE status='queued'`), jamais un SELECT puis un UPDATE sans garde ;
 *  2. **un bail, pas une propriété** : un worker qui meurt libère la tâche à l'expiration
 *     du lease, la file ne se bloque pas ;
 *  3. **aucun achèvement sur une tâche volée** : `complete` exige `locked_by = worker`.
 *
 * Comme pour `videos.repo.js`, la portée (propriétaire vs `videos:manage-jobs`) est décidée
 * dans le service, jamais ici.
 */

const KINDS = ['probe', 'transcode', 'transcribe', 'thumbnail', 'moderation'];
const STATUSES = ['queued', 'running', 'succeeded', 'failed', 'cancelled'];

export function createVideoJobsRepository(db) {
  function getById(id) {
    return db.get(`SELECT * FROM video_jobs WHERE id = ?`, [id]);
  }

  function getByVideoKind(videoId, kind) {
    return db.get(`SELECT * FROM video_jobs WHERE video_id = ? AND kind = ?`, [videoId, kind]);
  }

  /**
   * Mise en file, idempotente par `(video_id, kind)` : rejouer une analyse remet la ligne
   * existante en `queued` et oublie son résultat précédent, au lieu d'empiler des doublons.
   */
  function enqueue({ videoId, fileId, ownerId, kind, input = null, maxAttempts = 3, priority = 5, runAfter = null, jobTaskId = null }) {
    const k = KINDS.includes(kind) ? kind : 'probe';
    const now = new Date().toISOString();
    db.run(
      `INSERT INTO video_jobs (video_id, file_id, owner_id, kind, status, max_attempts, priority, run_after, input_json, job_task_id, created_at, updated_at)
       VALUES (?,?,?,?, 'queued', ?,?,?,?, ?,?,?)
       ON CONFLICT (video_id, kind) DO UPDATE SET
         status = 'queued', attempts = 0, error_code = NULL, error_message = NULL, progress = NULL,
         result_json = NULL, locked_by = NULL, locked_at = NULL, lease_expires_at = NULL, finished_at = NULL,
         max_attempts = excluded.max_attempts, priority = excluded.priority, run_after = excluded.run_after,
         input_json = excluded.input_json, job_task_id = excluded.job_task_id, updated_at = excluded.updated_at`,
      [videoId, fileId, ownerId, k, clampInt(maxAttempts, 1, 16), clampInt(priority, 0, 9), runAfter,
        input ? bounded(input, 8000) : null, jobTaskId, now, now],
    );
    return getByVideoKind(videoId, k);
  }

  /** Tâche réclamable la plus prioritaire (puis la plus ancienne). */
  /** `kinds` borne le prélèvement : un worker ne saisit que ce qu’il sait exécuter. */
  function nextClaimable({ now = new Date().toISOString(), kinds = KINDS } = {}) {
    const list = KINDS.filter((k) => kinds.includes(k));
    if (!list.length) return null;
    const placeholders = list.map(() => '?').join(',');
    return db.get(
      `SELECT id, video_id, file_id, owner_id, kind, attempts, max_attempts, input_json
         FROM video_jobs
        WHERE status = 'queued'
          AND kind IN (${placeholders})
          AND (run_after IS NULL OR run_after <= ?)
        ORDER BY priority DESC, id ASC
        LIMIT 1`,
      [...list, now],
    ) ?? null; // « rien à prendre » se dit null, pas undefined : la file n'a pas deux absences
  }

  /** Claim atomique : la garde `status='queued'` dans le WHERE est ce qui départage les workers. */
  function claim({ worker, kinds, leaseMs = 120_000, now = new Date() }) {
    const nowIso = now.toISOString();
    return db.tx(() => {
      const cand = nextClaimable({ now: nowIso, kinds });
      if (!cand) return null;
      const res = db.run(
        `UPDATE video_jobs
            SET status = 'running', locked_by = ?, locked_at = ?, lease_expires_at = ?,
                attempts = attempts + 1, started_at = COALESCE(started_at, ?), progress = 0,
                error_code = NULL, updated_at = ?
          WHERE id = ? AND status = 'queued'`,
        [String(worker).slice(0, 64), nowIso, new Date(now.getTime() + Math.max(1000, leaseMs)).toISOString(), nowIso, nowIso, cand.id],
      );
      if (!res.changes) return null; // un autre worker a été plus rapide : ce n'est pas une erreur
      return { ...cand, attempts: (cand.attempts ?? 0) + 1 };
    });
  }

  function heartbeat({ id, worker, leaseMs = 120_000, progress = null, now = new Date() }) {
    const nowIso = now.toISOString();
    const res = db.run(
      `UPDATE video_jobs SET lease_expires_at = ?, progress = COALESCE(?, progress), updated_at = ?
        WHERE id = ? AND status = 'running' AND locked_by = ?`,
      [new Date(now.getTime() + Math.max(1000, leaseMs)).toISOString(), progress == null ? null : clampInt(progress, 0, 100), nowIso, id, String(worker).slice(0, 64)],
    );
    return res.changes > 0;
  }

  /** Achèvement : uniquement par le détenteur du bail, sinon la tâche a été reprise entre-temps. */
  function finish({ id, worker, ok, result = null, errorCode = null, errorMessage = null, requeueAfter = null, now = new Date() }) {
    const nowIso = now.toISOString();
    return db.tx(() => {
      const row = getById(id);
      if (!row || row.status !== 'running' || row.locked_by !== String(worker).slice(0, 64)) return { lost: true, row };
      const exhausted = ok ? false : (row.attempts ?? 0) >= (row.max_attempts ?? 3);
      const status = ok ? 'succeeded' : exhausted ? 'failed' : 'queued';
      db.run(
        `UPDATE video_jobs
            SET status = ?, result_json = ?, error_code = ?, error_message = ?, progress = ?,
                run_after = ?, locked_by = NULL, locked_at = NULL, lease_expires_at = NULL,
                finished_at = ?, updated_at = ?
          WHERE id = ?`,
        [status, result ? bounded(result, 30_000) : row.result_json, ok ? null : boundedText(errorCode, 40), ok ? null : boundedText(errorMessage, 500),
          ok ? 100 : null, ok || exhausted ? null : requeueAfter, ok || exhausted ? nowIso : null, nowIso, id],
      );
      return { lost: false, row: getById(id), retrying: !ok && !exhausted };
    });
  }

  /** Ramassage : un bail expiré n'immobilise pas la file. */
  function reapExpired({ now = new Date(), requeueAfter = null } = {}) {
    const nowIso = now.toISOString();
    // `examined` est borné : après une panne prolongée le ramassage se fait par vagues, sinon un
    // seul tick pourrait tenir des dizaines de milliers de lignes et affamer la file saine.
    const STALE_BATCH = 500;
    const stale = db.all(
      `SELECT id, attempts, max_attempts FROM video_jobs
        WHERE status = 'running' AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
        ORDER BY id ASC
        LIMIT ${STALE_BATCH}`,
      [nowIso],
    );
    let failed = 0;
    let requeued = 0;
    for (const row of stale) {
      const exhausted = (row.attempts ?? 0) >= (row.max_attempts ?? 3);
      const res = db.run(
        `UPDATE video_jobs
            SET status = ?, error_code = ?, error_message = ?, locked_by = NULL, locked_at = NULL,
                lease_expires_at = NULL, run_after = ?, finished_at = ?, updated_at = ?
          WHERE id = ? AND status = 'running'`,
        [exhausted ? 'failed' : 'queued', 'VIDEO_LEASE_EXPIRED', 'bail expiré : le worker ne s’est plus manifesté',
          exhausted ? null : requeueAfter ?? nowIso, exhausted ? nowIso : null, nowIso, row.id],
      );
      if (res.changes) exhausted ? (failed += 1) : (requeued += 1);
    }
    return { examined: stale.length, requeued, failed };
  }

  function cancel({ id, now = new Date() }) {
    const nowIso = now.toISOString();
    db.run(
      `UPDATE video_jobs SET status = 'cancelled', error_code = 'VIDEO_CANCELLED', locked_by = NULL, lease_expires_at = NULL,
                              finished_at = ?, updated_at = ?
        WHERE id = ? AND status IN ('queued','running')`,
      [nowIso, nowIso, id],
    );
    return getById(id);
  }

  function requeue({ id, runAfter = null, now = new Date() }) {
    const nowIso = now.toISOString();
    db.run(
      `UPDATE video_jobs SET status = 'queued', attempts = 0, error_code = NULL, error_message = NULL, result_json = NULL,
                              locked_by = NULL, locked_at = NULL, lease_expires_at = NULL, finished_at = NULL,
                              started_at = NULL, progress = NULL, run_after = ?, updated_at = ?
        WHERE id = ?`,
      [runAfter, nowIso, id],
    );
    return getById(id);
  }

  function list({ videoId = null, status = '', ownerId = null, limit = 50, offset = 0 } = {}) {
    const where = [];
    const args = [];
    if (videoId != null) {
      where.push('j.video_id = ?');
      args.push(videoId);
    }
    if (ownerId != null) {
      where.push('j.owner_id = ?');
      args.push(ownerId);
    }
    if (STATUSES.includes(status)) {
      where.push('j.status = ?');
      args.push(status);
    }
    const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const rows = db.all(
      `SELECT j.*, v.file_id AS asset_file_id, f.original_name AS file_name
         FROM video_jobs j
         JOIN video_assets v ON v.id = j.video_id
         JOIN files f ON f.id = j.file_id
         ${clause}
        ORDER BY j.id DESC
        LIMIT ? OFFSET ?`,
      [...args, clampInt(limit, 1, 200), clampInt(offset, 0, 1_000_000)],
    );
    const total = db.get(`SELECT count(*) AS c FROM video_jobs j ${clause}`, args).c;
    return { items: rows, total };
  }

  function stats({ ownerId = null } = {}) {
    const args = ownerId == null ? [] : [ownerId];
    const clause = ownerId == null ? '' : 'WHERE owner_id = ?';
    const byStatus = db.all(`SELECT status, count(*) AS n, sum(length(COALESCE(result_json,''))) AS bytes FROM video_jobs ${clause} GROUP BY status`, args);
    const oldest = db.get(`SELECT min(created_at) AS at FROM video_jobs WHERE status = 'queued' ${ownerId == null ? '' : 'AND owner_id = ?'}`, args);
    // Scoping identique au reste : un compte standard ne compte pas les bails perdus d’autrui.
    const expiredArgs = ownerId == null ? [new Date().toISOString()] : [ownerId, new Date().toISOString()];
    const expired = db.get(
      `SELECT count(*) AS c FROM video_jobs
        WHERE status = 'running' AND (lease_expires_at IS NULL OR lease_expires_at <= ?)${ownerId == null ? '' : ' AND owner_id = ?'}`,
      ownerId == null ? expiredArgs : [expiredArgs[1], expiredArgs[0]],
    ).c;
    return { byStatus, queuedOldest: oldest?.at ?? null, expiredLeases: expired };
  }

  /** Jobs abandonnés (échoués ou annulés) plus anciens que la borne : nettoyage de fin de run. */
  function purgeFinished({ before, kinds = KINDS } = {}) {
    const list = KINDS.filter((k) => kinds.includes(k));
    if (!list.length || !before) return { removed: 0 };
    const placeholders = list.map(() => '?').join(',');
    const res = db.run(
      `DELETE FROM video_jobs WHERE status IN ('succeeded','failed','cancelled') AND updated_at < ? AND kind IN (${placeholders})`,
      [before, ...list],
    );
    return { removed: res.changes };
  }

  return { KINDS, STATUSES, getById, getByVideoKind, enqueue, nextClaimable, claim, heartbeat, finish, reapExpired, cancel, requeue, list, stats, purgeFinished };
}

function clampInt(v, min, max) {
  const n = Number(v);
  if (!Number.isFinite(n)) return min;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

function boundedText(v, max) {
  if (v == null) return null;
  return String(v).replace(/[\u0000-\u0008]/g, '').slice(0, max);
}

function bounded(v, max) {
  const text = typeof v === 'string' ? v : JSON.stringify(v);
  return text.length <= max ? text : JSON.stringify({ truncated: true, note: 'charge reduite pour tenir la colonne' });
}

export { KINDS as VIDEO_JOB_KINDS, STATUSES as VIDEO_JOB_STATUSES };
