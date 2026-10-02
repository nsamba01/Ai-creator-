/**
 * File routes.
 *
 * Uploads are parsed in memory (never written to disk by multer), validated,
 * then stored with a generated name under the private data volume. Downloads
 * are streamed by the application — the upload directory is never exposed as
 * static content, so no uploaded file can be executed or rendered inline.
 */
import fs from 'node:fs';
import { Router } from 'express';
import multer from 'multer';
import { createUploadMiddleware } from '../middleware/upload.js';
import { wrap, noStore, pagination } from './_helpers.js';
import { validateBody, S } from '../middleware/validate.js';
import { badRequest, forbidden, notFound, unsupportedMedia } from '../utils/errors.js';
import { FORBIDDEN_EXTENSIONS, classifyExtension } from '../services/files.service.js';

export function createFileRoutes(runtime) {
  const router = Router();
  const { db, config, audit, rbac, files } = runtime;
  const { requireAuth, requirePermission } = runtime.middlewares;

  const upload = createUploadMiddleware(multer({
    storage: multer.memoryStorage(),
    preservePath: false,
    limits: {
      fileSize: config.uploads.maxBytes,
      files: 1,
      fields: 4,
      fieldNameSize: 64,
      fieldSize: 512,
    },
    fileFilter(req, file, cb) {
      const { ext } = classifyExtension(file.originalname);
      if (FORBIDDEN_EXTENSIONS.has(ext)) {
        const err = unsupportedMedia(`Type refusé à l’entrée (${ext}).`);
        err.code = 'FILE_TYPE_REFUSED';
        return cb(err);
      }
      return cb(null, true);
    },
  }), config);

  router.post('/', requireAuth, noStore, upload.single('file'), wrap(async (req, res) => {
    if (!req.file) throw badRequest('Aucun fichier reçu (champ « file » attendu).');
    const maxBytes = Math.min(config.uploads.maxBytes, runtime.settings.number('files.max_upload_mb', Math.round(config.uploads.maxBytes / 1024 / 1024)) * 1024 * 1024);
    const { file, duplicate } = files.store({
      owner: req.user,
      originalName: req.file.originalname,
      mimeType: req.file.mimetype,
      buffer: req.file.buffer,
      maxBytes,
    });
    res.status(duplicate ? 200 : 201).json({ file, duplicate });
  }));

  router.get('/', requireAuth, noStore, wrap(async (req, res) => {
    const { limit, offset } = pagination(req.query, { limit: 50, max: 200 });
    // « files:read » autorise la lecture de SES propres fichiers ; seule
    // « files:read:any » ouvre la vue globale (sinon tout utilisateur lit les
    // fichiers d’autrui en devinant un identifiant).
    const canSeeAll = rbac.can(req.user, 'files:read:any');
    const out = files.list({
      ownerId: canSeeAll && req.query.scope !== 'mine' ? null : req.user.id,
      limit,
      offset,
      q: String(req.query.q ?? '').slice(0, 80),
    });
    res.json({ ...out, scope: canSeeAll && req.query.scope !== 'mine' ? 'all' : 'own' });
  }));

  router.get('/stats', requireAuth, requirePermission('files:read'), noStore, wrap(async (req, res) => {
    const global = rbac.can(req.user, 'files:read:any');
    const scoped = global ? files.stats() : files.statsForUser(req.user.id);
    res.json({ ...scoped, scope: global ? 'all' : 'own', policy: { maxUploadBytes: config.uploads.maxBytes, enforceMagic: config.uploads.enforceMagic, quotaBytes: config.uploads.quotaBytes ?? 500 * 1024 * 1024 } });
  }));

  router.get('/:id', requireAuth, noStore, wrap(async (req, res) => {
    const dto = files.getById(Number(req.params.id));
    if (!dto) throw notFound('Fichier introuvable.');
    assertReadable(req, dto, rbac);
    // Les produits dérivés (vignette, piste audio) suivent la portée de la source : celui qui lit le
    // parent lit ses artefacts, et seulement les leurs — la liste n'est jamais ouverte par identifiant.
    res.json({ file: dto, children: files.childrenOf(dto.id) });
  }));

  router.get('/:id/content', requireAuth, wrap(async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) throw badRequest('Identifiant invalide.');
    const { row, abs } = files.readAbsolute(id);
    assertReadable(req, { ownerId: row.owner_id }, rbac, 'files:read:any');
    const stat = fs.statSync(abs);
    res.setHeader('Content-Type', mapSafeContentType(row.mime_type, row.extension));
    res.setHeader('Content-Length', String(stat.size));
    res.setHeader('Content-Disposition', disposition(row.original_name, req.query.inline === '1'));
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox; style-src 'unsafe-inline'; img-src 'self' data:");
    res.setHeader('Cache-Control', 'private, max-age=0, must-revalidate');
    audit.record({
      req,
      actor: req.user,
      action: audit.AUDIT.FILE_DOWNLOADED,
      category: 'files',
      target_type: 'file',
      target_id: row.id,
      detail: { name: row.original_name, size: stat.size },
    });
    db.run(`UPDATE files SET download_count = download_count + 1 WHERE id = ?`, [row.id]);
    fs.createReadStream(abs).pipe(res);
  }));

  router.delete('/:id', requireAuth, noStore, wrap(async (req, res) => {
    const id = Number(req.params.id);
    const dto = files.getById(id);
    if (!dto) throw notFound('Fichier introuvable.');
    const isOwner = dto.ownerId === req.user.id;
    if (!isOwner && !rbac.can(req.user, 'files:delete:any')) throw forbidden('Permission files:delete:any requise.');
    files.remove(id, req.user);
    res.json({ ok: true, deleted: id });
  }));

  return router;
}

function assertReadable(req, dto, rbac, perm = 'files:read:any') {
  if (dto.ownerId === req.user.id) return;
  if (rbac.can(req.user, perm)) return;
  throw forbidden('Accès refusé à ce fichier.');
}

/** Never lets a stored document become an active content in the browser. */
function mapSafeContentType(mime, ext) {
  const safe = {
    'image/png': 'image/png',
    'image/jpeg': 'image/jpeg',
    'image/gif': 'image/gif',
    'image/webp': 'image/webp',
    'image/bmp': 'image/bmp',
    'audio/wav': 'audio/wav',
    'application/pdf': 'application/pdf',
    'text/plain': 'text/plain; charset=utf-8',
  };
  return safe[mime] ?? 'application/octet-stream';
}

function disposition(name, inline) {
  const cleaned = String(name).replace(/[^\w.\- ()]/g, '_').slice(0, 120) || 'file';
  return `${inline ? 'inline' : 'attachment'}; filename="${cleaned}"; filename*=UTF-8''${encodeURIComponent(cleaned)}`;
}

export default createFileRoutes;
