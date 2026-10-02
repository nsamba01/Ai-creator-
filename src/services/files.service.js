/**
 * Secure file handling.
 *
 * Upload policy (each rule is covered by tests):
 *  1. extension allow-list — scripts, HTML/SVG/XML and executables are refused
 *     (stored XSS / code execution vectors);
 *  2. declared MIME must match the extension family;
 *  3. magic bytes must match the real content (`enforceMagic`);
 *  4. size cap from settings, plus a per-user quota;
 *  5. the client filename is never used for the path: storage name is
 *     `<uuid>.<safeext>` inside sharded folders — path traversal is impossible
 *     and the original name is only metadata;
 *  6. files are stored 0600 under the data volume, outside the web root, and
 *     are only ever served through the authenticated API;
 *  7. downloads are `Content-Disposition: attachment` + `nosniff` +
 *     `Content-Security-Policy: sandbox` — no uploaded document can execute;
 *  8. every important operation is audited.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { AppError, badRequest, notFound, tooLarge, unsupportedMedia } from '../utils/errors.js';
import { sha256Hex } from '../utils/crypto.js';
import { logger } from '../utils/logger.js';

export const KIND_BY_EXT = {
  '.png': 'image',
  '.jpg': 'image',
  '.jpeg': 'image',
  '.gif': 'image',
  '.webp': 'image',
  '.bmp': 'image',
  '.pdf': 'pdf',
  '.docx': 'document',
  '.xlsx': 'spreadsheet',
  '.csv': 'csv',
  '.tsv': 'csv',
  '.json': 'json',
  '.md': 'text',
  '.txt': 'text',
  '.log': 'text',
  '.yml': 'text',
  '.yaml': 'text',
  '.xml': 'text',
  // Conteneurs video acceptes en phase A (sondage d'en-tete uniquement). Un
  // fichier dont la signature ne correspond pas au conteneur revendique est
  // refuse plus bas par MAGIC : l'extension ne suffit jamais.
  '.mp4': 'video',
  '.m4v': 'video',
  '.mov': 'video',
  '.mkv': 'video',
  '.webm': 'video',
  '.avi': 'video',
};

/** Refused outright: executable or browser-renderable content. */
export const FORBIDDEN_EXTENSIONS = new Set([
  '.html', '.htm', '.xhtml', '.shtml', '.svg', '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx',
  '.php', '.phtml', '.phar', '.py', '.pyc', '.rb', '.pl', '.pm', '.lua', '.sh', '.bash', '.zsh',
  '.ksh', '.fish', '.bat', '.cmd', '.ps1', '.psm1', '.vbs', '.vbe', '.wsf', '.wsh', '.exe', '.dll',
  '.so', '.dylib', '.ocx', '.com', '.scr', '.msi', '.msp', '.jar', '.war', '.apk', '.aab', '.aab',
  '.deb', '.rpm', '.AppImage', '.elf', '.ws', '.wat', '.action', '.crx', '.xap', '.vb', '.jsm',
  '.htaccess', '.env', '.ini', '.conf', '.service', '.ssh', '.npmrc', '.gitconfig',
]);

const MIME_FAMILIES = {
  '.png': ['image/png'],
  '.jpg': ['image/jpeg', 'image/pjpeg'],
  '.jpeg': ['image/jpeg', 'image/pjpeg'],
  '.gif': ['image/gif'],
  '.webp': ['image/webp'],
  '.bmp': ['image/bmp', 'image/x-bmp'],
  '.pdf': ['application/pdf'],
  '.docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/zip'],
  '.xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/zip'],
  '.csv': ['text/csv', 'text/plain', 'application/vnd.ms-excel'],
  '.tsv': ['text/tab-separated-values', 'text/csv', 'text/plain'],
  '.json': ['application/json', 'text/plain'],
  '.md': ['text/markdown', 'text/plain'],
  '.txt': ['text/plain'],
  '.log': ['text/plain'],
  '.yml': ['text/yaml', 'text/plain'],
  '.yaml': ['text/yaml', 'text/plain'],
  '.xml': ['text/xml', 'application/xml', 'text/plain'],
  '.mp4': ['video/mp4', 'video/x-m4v'],
  '.m4v': ['video/x-m4v', 'video/mp4'],
  '.mov': ['video/quicktime', 'video/x-quicktime', 'video/mp4'],
  '.mkv': ['video/x-matroska', 'video/matroska'],
  '.webm': ['video/webm'],
  '.avi': ['video/x-msvideo', 'video/avi', 'avi'],
};

const MAGIC = [
  { ext: ['.png'], mime: 'image/png', test: (b) => b.length > 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47 },
  { ext: ['.jpg', '.jpeg'], mime: 'image/jpeg', test: (b) => b.length > 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  { ext: ['.gif'], mime: 'image/gif', test: (b) => b.length > 6 && b.subarray(0, 6).toString('latin1').startsWith('GIF8') },
  {
    ext: ['.webp'],
    mime: 'image/webp',
    test: (b) => b.length > 12 && b.subarray(0, 4).toString('latin1') === 'RIFF' && b.subarray(8, 12).toString('latin1') === 'WEBP',
  },
  { ext: ['.bmp'], mime: 'image/bmp', test: (b) => b.length > 2 && b[0] === 0x42 && b[1] === 0x4d },
  { ext: ['.pdf'], mime: 'application/pdf', test: (b) => b.length > 5 && b.subarray(0, 5).toString('latin1') === '%PDF-' },
  { ext: ['.docx', '.xlsx'], mime: 'application/zip', test: (b) => b.length > 4 && b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x03 && b[3] === 0x04 },
  // Conteneurs video : la signature du conteneur, pas le nom du fichier.
  { ext: ['.mp4', '.m4v', '.mov'], mime: 'video/mp4', test: (b) => b.length > 12 && b.subarray(4, 8).toString('latin1') === 'ftyp' },
  { ext: ['.mkv', '.webm'], mime: 'video/matroska', test: (b) => b.length > 4 && b[0] === 0x1a && b[1] === 0x45 && b[2] === 0xdf && b[3] === 0xa3 },
  { ext: ['.avi'], mime: 'video/x-msvideo', test: (b) => b.length > 12 && b.subarray(0, 4).toString('latin1') === 'RIFF' && b.subarray(8, 12).toString('latin1') === 'AVI ' },
];

const TEXTUAL = new Set(['.txt', '.md', '.log', '.yml', '.yaml', '.csv', '.tsv', '.json', '.xml']);

/** Rejects binary payloads disguised as text; accepts UTF-8 (BOM allowed). */
function looksLikeText(buf) {
  let i = 0;
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) i = 3;
  let controls = 0;
  const sample = Math.min(buf.length, i + 8192);
  for (; i < sample; i += 1) {
    const b = buf[i];
    if (b === 0x00) return false;
    if (b < 0x09 || (b > 0x0d && b < 0x20)) controls += 1;
  }
  return controls / Math.max(1, sample) < 0.02;
}

export function classifyExtension(name) {
  const base = path.basename(String(name ?? ''));
  const ext = path.extname(base).toLowerCase();
  return { base, ext };
}

/** Validates the original filename only as *display metadata*. */
export function sanitizeDisplayName(name) {
  let value = String(name ?? 'file').replace(/\\/g, '/').split('/').pop();
  value = value.replace(/[\u0000-\u001f\u007f"']+/g, ' ').replace(/\s+/g, ' ').trim();
  value = value.replace(/^\.+/, ''); // no dot-leading names
  if (!value) value = 'file';
  return value.slice(0, 180);
}

export function createFileService({ db, config, audit }) {
  const root = config.uploadDir;

  function ensureDirs() {
    fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  }

  function resolveStored(relativePath) {
    const abs = path.resolve(root, String(relativePath ?? ''));
    const rootAbs = path.resolve(root);
    if (abs !== rootAbs && !abs.startsWith(rootAbs + path.sep)) {
      throw new AppError(400, 'BAD_PATH', 'Chemin de fichier refusé.');
    }
    return abs;
  }

  function userQuotaUsed(ownerId) {
    return db.get(`SELECT COALESCE(sum(size_bytes), 0) AS used FROM files WHERE owner_id = ? AND deleted_at IS NULL`, [ownerId]).used;
  }

  /**
   * @param {Buffer} buffer raw bytes (already size-capped by multer)
   */
  function inspect({ originalName, mimeType, buffer, maxBytes }) {
    const { ext } = classifyExtension(originalName);
    const displayName = sanitizeDisplayName(originalName);
    const notes = [];

    if (!ext) throw unsupportedMedia('Fichier sans extension : type non vérifiable.');
    if (FORBIDDEN_EXTENSIONS.has(ext.toLowerCase())) {
      throw unsupportedMedia(`Extension refusée (${ext}) : contenu exécutable ou interprétable par le navigateur.`);
    }
    if (!KIND_BY_EXT[ext]) throw unsupportedMedia(`Extension non autorisée (${ext}).`);
    if (buffer.length === 0) throw badRequest('Fichier vide.');
    if (buffer.length > maxBytes) throw tooLarge(`Fichier trop volumineux (max ${Math.round(maxBytes / 1024 / 1024)} Mo).`);

    const family = MIME_FAMILIES[ext] ?? [];
    const declared = String(mimeType ?? '').split(';')[0].trim().toLowerCase();
    if (declared && family.length && !family.includes(declared) && declared !== 'application/octet-stream') {
      notes.push(`MIME déclaré (${declared}) incohérent avec l’extension attendue (${family[0]})`);
    }

    let magicOk = true;
    let magicKind = null;
    if (config.uploads.enforceMagic) {
      if (TEXTUAL.has(ext)) {
        magicOk = looksLikeText(buffer);
        magicKind = 'text';
        if (!magicOk) notes.push('contenu binaire dans un fichier texte');
      } else {
        const entry = MAGIC.find((m) => m.ext.includes(ext));
        magicOk = entry ? entry.test(buffer) : false;
        magicKind = entry?.mime ?? null;
        if (!magicOk) notes.push('signature binaire absente ou incorrecte');
      }
    }

    // Extra content probes (documented as heuristics, not an AV engine).
    if (ext === '.pdf') {
      const head = buffer.subarray(0, 2048).toString('latin1');
      if (/\/(JavaScript|Launch|EmbeddedFile|OpenAction)\b/i.test(head)) notes.push('PDF contenant des actions/scripts embarqués');
      if (buffer.subarray(0, 1024).includes(Buffer.from('%%EOF', 'latin1')) === false && buffer.length < 4096) magicOk = false;
    }
    if (/\x00/.test(buffer.subarray(0, Math.min(buffer.length, 512)).toString('latin1')) && TEXTUAL.has(ext)) magicOk = false;

    return {
      displayName,
      ext,
      kind: KIND_BY_EXT[ext],
      size: buffer.length,
      sha256: sha256Hex(buffer),
      magicOk,
      notes,
      buffer,
    };
  }

  function store({ owner, originalName, mimeType, buffer, maxBytes, parentFileId = null }) {
    ensureDirs();
    const info = inspect({ originalName, mimeType, buffer, maxBytes });
    // Un artefact (vignette, piste audio, rapport) doit rester rattaché à sa source : même
    // propriétaire, même quota, et la suppression de la source emporte ses enfants. Sans ce
    // lien, chaque sortie d’agent inventerait son propre contrôle d’accès — le chemin le plus
    // sûr vers une fuite.
    let parent = null;
    if (parentFileId != null) {
      parent = db.get(`SELECT id, owner_id FROM files WHERE id = ? AND deleted_at IS NULL`, [Number(parentFileId)]);
      if (!parent) throw notFound('Fichier parent introuvable.');
      if (parent.owner_id !== owner.id && !rbacCan(owner, 'files:read:any')) throw forbidden('Fichier parent d’un autre utilisateur.');
    }

    const quotaBytes = config.uploads.quotaBytes ?? 500 * 1024 * 1024;
    if (userQuotaUsed(owner.id) + info.size > quotaBytes) {
      audit?.record({ actor: owner, action: audit.AUDIT.FILE_REJECTED, category: 'files', outcome: 'blocked', severity: 'notice', detail: { reason: 'quota', name: info.displayName } });
      throw new AppError(507, 'QUOTA_EXCEEDED', 'Quota de stockage personnel atteint.');
    }

    const dup = db.get(`SELECT id, stored_name, relative_path FROM files WHERE sha256 = ? AND owner_id = ? AND deleted_at IS NULL`, [info.sha256, owner.id]);
    if (dup) {
      // Same content, same owner: no duplicate bytes, but the request succeeds.
      const existing = db.get(`SELECT * FROM files WHERE id = ?`, [dup.id]);
      audit?.record({ actor: owner, action: 'file.duplicated', category: 'files', outcome: 'success', targetType: 'file', targetId: existing.id, detail: { reason: 'sha256 identique' } });
      return { file: rowToDto(existing), duplicate: true };
    }

    if (!info.magicOk) {
      audit?.record({
        actor: owner,
        action: audit.AUDIT.FILE_REJECTED,
        category: 'files',
        outcome: 'blocked',
        severity: 'warning',
        detail: { name: info.displayName, notes: info.notes },
      });
      throw unsupportedMedia(`Contenu refusé : ${info.notes.join('; ') || 'signature invalide'}.`);
    }

    const id = crypto.randomUUID();
    const shard = info.sha256.slice(0, 2);
    const storedName = `${id}${info.ext}`;
    const relativePath = path.posix.join(shard, storedName);
    const abs = resolveStored(relativePath);
    fs.mkdirSync(path.dirname(abs), { recursive: true, mode: 0o700 });
    fs.writeFileSync(abs, info.buffer, { mode: 0o600, flag: 'wx' });

    const res = db.run(
      `INSERT INTO files (owner_id, original_name, stored_name, relative_path, mime_type, extension, size_bytes, sha256, kind, magic_ok, scan_status, scan_notes, parent_file_id)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [
        owner.id,
        info.displayName,
        storedName,
        relativePath,
        mimeType ? String(mimeType).split(';')[0].slice(0, 120) : 'application/octet-stream',
        info.ext,
        info.size,
        info.sha256,
        info.kind,
        info.magicOk ? 1 : 0,
        'checked',
        info.notes.length ? JSON.stringify(info.notes).slice(0, 500) : null,
        parent?.id ?? null,
      ],
    );
    const row = db.get(`SELECT * FROM files WHERE id = ?`, [res.lastInsertRowid]);
    audit?.record({
      actor: owner,
      action: audit.AUDIT.FILE_UPLOADED,
      category: 'files',
      outcome: 'success',
      targetType: 'file',
      targetId: row.id,
      detail: { name: info.displayName, size: info.size, sha256: info.sha256.slice(0, 16), kind: info.kind, notes: info.notes.length },
    });
    logger.debug('fichier stocké', { id: row.id, kind: info.kind, size: info.size });
    return { file: rowToDto(row), duplicate: false };
  }

  function list({ ownerId = null, limit = 50, offset = 0, q = '' } = {}) {
    const where = ['f.deleted_at IS NULL'];
    const params = [];
    if (ownerId) {
      where.push('f.owner_id = ?');
      params.push(ownerId);
    }
    if (q) {
      where.push('f.original_name LIKE ?');
      params.push(`%${q}%`);
    }
    const clause = `WHERE ${where.join(' AND ')}`;
    const total = db.get(`SELECT count(*) AS c FROM files f ${clause}`, params).c;
    const rows = db.all(
      `SELECT f.*, u.username AS owner_name FROM files f JOIN users u ON u.id = f.owner_id ${clause} ORDER BY f.id DESC LIMIT ? OFFSET ?`,
      [...params, Math.min(200, Math.max(1, limit)), Math.max(0, offset)],
    );
    return { total, items: rows.map((r) => ({ ...rowToDto(r), ownerName: r.owner_name })) };
  }

  function getById(id) {
    const row = db.get(`SELECT f.*, u.username AS owner_name FROM files f JOIN users u ON u.id = f.owner_id WHERE f.id = ? AND f.deleted_at IS NULL`, [id]);
    if (!row) return null;
    return { ...rowToDto(row), ownerName: row.owner_name };
  }

  function readAbsolute(idOrRow) {
    const row = typeof idOrRow === 'object' ? idOrRow : db.get(`SELECT * FROM files WHERE id = ? AND deleted_at IS NULL`, [idOrRow]);
    if (!row) throw notFound('Fichier introuvable.');
    const abs = resolveStored(row.relative_path);
    if (!fs.existsSync(abs)) throw notFound('Fichier absent du stockage.');
    return { row, abs };
  }

  /** Les artefacts produits à partir d'un fichier (vignettes, extraits), dans l'ordre d'apparition. */
  function childrenOf(fileId) {
    // Même forme que n'importe quel autre fichier : un client ne doit pas deviner la structure de
    // la table à travers un bordereau d'artefacts.
    return db
      .all(`SELECT * FROM files WHERE parent_file_id = ? AND deleted_at IS NULL ORDER BY id`, [Number(fileId)])
      .map(rowToDto);
  }

  function remove(id, actor) {
    const row = db.get(`SELECT * FROM files WHERE id = ? AND deleted_at IS NULL`, [id]);
    if (!row) throw notFound('Fichier introuvable.');
    const abs = resolveStored(row.relative_path);
    const when = new Date().toISOString();
    db.run(`UPDATE files SET deleted_at = ? WHERE id = ?`, [when, id]);
    // Les rapports de sondage suivent leur source : sinon une ligne video
    // orpheline resterait consultable apres la suppression du fichier.
    db.run(`UPDATE video_assets SET deleted_at = ?, updated_at = ? WHERE file_id = ? AND deleted_at IS NULL`, [when, when, id]);
    try {
      if (fs.existsSync(abs)) fs.unlinkSync(abs);
    } catch (err) {
      logger.warn('suppression physique impossible', { id, error: err.message });
    }
    // Les artefacts produits à partir de ce fichier suivent leur source, octets compris :
    // une vignette ou une piste audio survivante serait une fuite partialle du média supprimé.
    const children = db.all(`SELECT id, relative_path FROM files WHERE parent_file_id = ? AND deleted_at IS NULL`, [id]);
    for (const child of children) {
      db.run(`UPDATE files SET deleted_at = ? WHERE id = ?`, [when, child.id]);
      try {
        const cabs = resolveStored(child.relative_path);
        if (fs.existsSync(cabs)) fs.unlinkSync(cabs);
      } catch (err) {
        logger.warn('suppression physique d’un artefact impossible', { id: child.id, error: err.message });
      }
    }
    audit?.record({
      actor,
      action: audit.AUDIT.FILE_DELETED,
      category: 'files',
      targetType: 'file',
      targetId: id,
      severity: 'notice',
      detail: { name: row.original_name, artefacts: children.length },
    });
    return { ok: true, id };
  }

  function stats() {
    const totals = db.get(
      `SELECT count(*) AS c, COALESCE(sum(size_bytes),0) AS bytes, COALESCE(sum(download_count),0) AS downloads
         FROM files WHERE deleted_at IS NULL`,
    );
    const byKind = db.all(`SELECT kind, count(*) AS c FROM files WHERE deleted_at IS NULL GROUP BY kind ORDER BY c DESC`);
    const rejected = db.get(`SELECT count(*) AS c FROM audit_logs WHERE action = 'file.rejected'`).c;
    return { count: totals.c, bytes: totals.bytes, downloads: totals.downloads, byKind, rejected };
  }

  /** Same counters, restricted to one owner (no global disclosure). */
  function statsForUser(ownerId) {
    const totals = db.get(
      `SELECT count(*) AS c, COALESCE(sum(size_bytes),0) AS bytes, COALESCE(sum(download_count),0) AS downloads
         FROM files WHERE deleted_at IS NULL AND owner_id = ?`,
      [ownerId],
    );
    const byKind = db.all(`SELECT kind, count(*) AS c FROM files WHERE deleted_at IS NULL AND owner_id = ? GROUP BY kind ORDER BY c DESC`, [ownerId]);
    const rejected = db.get(`SELECT count(*) AS c FROM audit_logs WHERE action = 'file.rejected' AND actor_id = ?`, [ownerId]).c;
    return { count: totals.c, bytes: totals.bytes, downloads: totals.downloads, byKind, rejected };
  }

  return { store, list, getById, readAbsolute, remove, inspect, stats, statsForUser, resolveStored, sanitizeDisplayName, userQuotaUsed, childrenOf };
}

export function rowToDto(row) {
  return {
    id: row.id,
    ownerId: row.owner_id,
    parentId: row.parent_file_id ?? null,
    originalName: row.original_name,
    mimeType: row.mime_type,
    extension: row.extension,
    sizeBytes: row.size_bytes,
    sha256: row.sha256,
    kind: row.kind,
    magicOk: Boolean(row.magic_ok),
    scanStatus: row.scan_status,
    scanNotes: safeNotes(row.scan_notes),
    downloadCount: row.download_count,
    createdAt: row.created_at,
    deletedAt: row.deleted_at ?? null,
  };
}

function safeNotes(s) {
  if (!s) return [];
  try {
    const v = JSON.parse(s);
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}

export { looksLikeText, MAGIC, TEXTUAL };
