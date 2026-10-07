/**
 * Accès SQL du périmètre vidéo.
 *
 * Règles : requêtes paramétrées uniquement, pas d'interpolation de valeurs,
 * et un seul endroit où l'on touche `video_assets` / `video_analyses` — la
 * portée (propriétaire vs `videos:read:any`) est décidée dans le service, jamais ici.
 */

/**
 * Filet de sécurité : une chaîne déjà produite ne doit jamais être rentrées de force dans la
 * colonne par découpage. Si elle déborde ou ne se relit pas, on y met un objet valide qui le
 * déclare — la perte reste lisible plutôt que silencieuse.
 */
function validJson(text, limit) {
  if (typeof text !== 'string' || !text) return null;
  if (text.length <= limit) {
    try {
      JSON.parse(text);
      return text;
    } catch {
      /* tombeau : on déclare la perte ci-dessous */
    }
  }
  return JSON.stringify({ truncated: true, note: 'rapport trop volumineux pour la colonne', kept: text.length });
}

export function createVideoRepository(db) {
  function createAsset({ fileId, ownerId, fileSize, sha256, taskId = null }) {
    const res = db.run(
      `INSERT INTO video_assets (file_id, owner_id, file_size_bytes, sha256, task_id, status, probe_source)
       VALUES (?,?,?,?,?,'pending','none')`,
      [fileId, ownerId, fileSize, sha256, taskId],
    );
    return getById(res.lastInsertRowid);
  }

  function getById(id) {
    return db.get(`SELECT * FROM video_assets WHERE id = ? AND deleted_at IS NULL`, [id]);
  }

  function getByFileId(fileId) {
    return db.get(`SELECT * FROM video_assets WHERE file_id = ? AND deleted_at IS NULL`, [fileId]);
  }

  /** Enregistrement du résultat d'un sondage : une seule ligne par fichier. */
  function applyProbe(id, fields) {
    db.run(
      `UPDATE video_assets
          SET container = ?, brand = ?, codec = ?, duration_ms = ?, width = ?, height = ?, fps = ?,
              bitrate_bps = ?, track_count = ?, parser = ?, probe_source = ?, status = ?, error_code = ?,
              notes = ?, meta_json = ?, probed_at = ?, updated_at = ?
        WHERE id = ?`,
      [
        str(fields.container, 24),
        str(fields.brand, 24),
        str(fields.codec, 32),
        num(fields.durationMs),
        num(fields.width),
        num(fields.height),
        real(fields.fps),
        num(fields.bitrateBps),
        num(fields.trackCount),
        str(fields.parser, 16),
        fields.probeSource ?? 'header',
        fields.status,
        str(fields.errorCode, 40),
        str(fields.notes, 1000),
        fields.metaJson ? validJson(String(fields.metaJson), 16_000) : null,
        new Date().toISOString(),
        new Date().toISOString(),
        id,
      ],
    );
    return getById(id);
  }

  function setStatus(id, { status, errorCode = null, notes = null }) {
    db.run(`UPDATE video_assets SET status = ?, error_code = ?, notes = COALESCE(?, notes), updated_at = ? WHERE id = ?`, [
      status,
      str(errorCode, 40),
      str(notes, 1000),
      new Date().toISOString(),
      id,
    ]);
    return getById(id);
  }

  function linkTask(id, taskId) {
    db.run(`UPDATE video_assets SET task_id = ? WHERE id = ?`, [taskId, id]);
  }

  /** Un seul rapport par (vidéo, kind) : un re-sondage remplace, il ne duplique pas. */
  function recordAnalysis({ videoId, kind = 'probe', status = 'ok', model = null, result = null, error = null, costMs = null }) {
    db.run(
      `INSERT INTO video_analyses (video_id, kind, status, model, result_json, error, cost_ms, created_at)
       VALUES (?,?,?,?,?,?,?,?)
       ON CONFLICT(video_id, kind) DO UPDATE SET
         status = excluded.status,
         model = excluded.model,
         result_json = excluded.result_json,
         error = excluded.error,
         cost_ms = excluded.cost_ms,
         created_at = excluded.created_at`,
      [videoId, kind, ['ok', 'partial', 'failed'].includes(status) ? status : 'ok', str(model, 40), result ? validJson(typeof result === 'string' ? result : JSON.stringify(result), 30_000) : null, str(error, 200), num(costMs), new Date().toISOString()],
    );
    return db.get(`SELECT * FROM video_analyses WHERE video_id = ? AND kind = ?`, [videoId, kind]);
  }

  function latestAnalyses(videoId) {
    return db.all(`SELECT * FROM video_analyses WHERE video_id = ? ORDER BY id DESC LIMIT 20`, [videoId]);
  }

  function list({ ownerId = null, status = '', limit = 25, offset = 0, q = '' } = {}) {
    const where = ['v.deleted_at IS NULL'];
    const params = [];
    if (ownerId) {
      where.push('v.owner_id = ?');
      params.push(ownerId);
    }
    if (status) {
      where.push('v.status = ?');
      params.push(status);
    }
    if (q) {
      where.push('f.original_name LIKE ?');
      params.push(`%${q}%`);
    }
    const clause = `WHERE ${where.join(' AND ')}`;
    const total = db.get(`SELECT count(*) AS c FROM video_assets v JOIN files f ON f.id = v.file_id ${clause}`, params).c;
    const rows = db.all(
      `SELECT v.*, f.original_name, f.mime_type, f.extension, f.deleted_at AS file_deleted_at, u.username AS owner_name
         FROM video_assets v
         JOIN files f ON f.id = v.file_id
         JOIN users u ON u.id = v.owner_id
        ${clause}
        ORDER BY v.id DESC LIMIT ? OFFSET ?`,
      [...params, Math.min(200, Math.max(1, limit)), Math.max(0, offset)],
    );
    return { total, rows };
  }

  /** Suppression logique en cascade avec le fichier source. */
  function softDeleteByFileId(fileId, when) {
    const res = db.run(`UPDATE video_assets SET deleted_at = ?, updated_at = ? WHERE file_id = ? AND deleted_at IS NULL`, [when, when, fileId]);
    return res.changes ?? 0;
  }

  function stats({ ownerId = null } = {}) {
    const scope = ownerId ? 'WHERE owner_id = ? AND deleted_at IS NULL' : 'WHERE deleted_at IS NULL';
    const params = ownerId ? [ownerId] : [];
    const totals = db.get(`SELECT count(*) AS c, COALESCE(sum(file_size_bytes),0) AS bytes FROM video_assets ${scope}`, params);
    const byStatus = db.all(`SELECT status, count(*) AS c FROM video_assets ${scope} GROUP BY status ORDER BY c DESC`, params);
    const quarantined = db.get(`SELECT count(*) AS c FROM video_assets ${scope.replace('WHERE deleted_at IS NULL', 'WHERE deleted_at IS NULL AND status = \'quarantined\'')}`, params).c;
    return { count: totals.c, bytes: totals.bytes, byStatus, quarantined };
  }

  return {
    createAsset,
    getById,
    getByFileId,
    applyProbe,
    setStatus,
    linkTask,
    recordAnalysis,
    latestAnalyses,
    list,
    softDeleteByFileId,
    stats,
  };
}

function str(v, max) {
  if (v === null || v === undefined || v === '') return null;
  return String(v).slice(0, max);
}

function num(v) {
  const n = Number(v);
  return Number.isFinite(n) ? Math.round(n) : null;
}

function real(v) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? Math.round(n * 1000) / 1000 : null;
}

export default createVideoRepository;
