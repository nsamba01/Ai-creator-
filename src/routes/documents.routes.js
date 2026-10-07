/**
 * Document analysis routes (Agent documentaire).
 *
 * Three entry points:
 *  - POST /api/documents/analyze      analyse a stored file by id
 *  - POST /api/documents/upload       store + analyse in one step
 *  - POST /api/documents/inline       analyse bounded text/csv/json content
 *
 * The returned payload is a digest: text is truncated, and every detected
 * secret is reported as a *count*, never as a value.
 */
import { Router } from 'express';
import multer from 'multer';
import { createUploadMiddleware } from '../middleware/upload.js';
import fs from 'node:fs';
import { wrap, noStore, pagination } from './_helpers.js';
import { validateBody, S } from '../middleware/validate.js';
import { badRequest, forbidden, notFound, unsupportedMedia } from '../utils/errors.js';
import { analyzeBuffer } from '../services/documents.service.js';
import { FORBIDDEN_EXTENSIONS, classifyExtension } from '../services/files.service.js';
import { utf8 } from '../services/documents.service.js';

const ANALYZABLE = new Set(['.txt', '.md', '.log', '.yml', '.yaml', '.json', '.csv', '.tsv', '.docx', '.xlsx', '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.xml']);

export function createDocumentRoutes(runtime) {
  const router = Router();
  const { db, config, audit, rbac, files } = runtime;
  const { requireAuth, requirePermission } = runtime.middlewares;

  const upload = createUploadMiddleware(multer({
    storage: multer.memoryStorage(),
    preservePath: false,
    limits: { fileSize: config.uploads.maxBytes, files: 1, fields: 2, fieldSize: 512 },
    fileFilter(req, file, cb) {
      const { ext } = classifyExtension(file.originalname);
      if (FORBIDDEN_EXTENSIONS.has(ext) || !ANALYZABLE.has(ext)) {
        const err = unsupportedMedia(`Type non analysable (${ext || 'inconnu'}).`);
        err.code = 'DOC_TYPE_REFUSED';
        return cb(err);
      }
      cb(null, true);
    },
  }), config);

  function persist({ actor, source, extension, status, summary, metrics, findings, fileId }) {
    const res = db.run(
      `INSERT INTO document_analyses (file_id, requested_by, source, extension, status, summary, metrics_json, findings_json, created_at)
       VALUES (?,?,?,?,?,?,?,?,?)`,
      [
        fileId ?? null,
        actor?.id ?? null,
        source,
        String(extension ?? '').slice(0, 10),
        ['ok', 'partial', 'failed'].includes(status) ? status : 'ok',
        String(summary ?? '').slice(0, 1000),
        metrics ? JSON.stringify(metrics).slice(0, 6000) : null,
        findings ? JSON.stringify(findings).slice(0, 6000) : null,
        new Date().toISOString(),
      ],
    );
    return res.lastInsertRowid;
  }

  function shape(out, { fileName, bytes, analysisId }) {
    return {
      analysisId,
      fileName,
      bytes,
      kind: out.kind,
      status: out.status,
      extraction: out.extraction ?? 'exacte',
      summary: out.summary,
      metrics: out.metrics,
      findings: out.findings,
      structure: out.structure ?? undefined,
      textPreview: typeof out.text === 'string' ? out.text.slice(0, 1500) : '',
      truncated: typeof out.text === 'string' ? out.text.length > 1500 : false,
    };
  }

  router.post('/analyze', requireAuth, requirePermission('documents:analyze'), noStore, validateBody({
    fileId: S.id({ label: 'identifiant de fichier' }),
    includeText: S.bool({ required: false, default: false }),
  }), wrap(async (req, res) => {
    const { fileId, includeText } = req.validated;
    const { row, abs } = files.readAbsolute(fileId);
    if (row.owner_id !== req.user.id && !rbac.can(req.user, 'files:read:any')) throw forbidden('Fichier d’un autre utilisateur.');
    const buffer = readCapped(abs, config.uploads.maxBytes);
    const out = analyzeBuffer(buffer, row.extension);
    const analysisId = persist({
      actor: req.user,
      source: 'upload',
      extension: row.extension,
      status: out.status,
      summary: out.summary,
      metrics: out.metrics,
      findings: out.findings,
      fileId: row.id,
    });
    audit.record({
      req,
      actor: req.user,
      action: audit.AUDIT.DOCUMENT_ANALYZED,
      category: 'agents',
      target_type: 'file',
      target_id: row.id,
      detail: { kind: out.kind, status: out.status, findings: out.findings.length },
    });
    const payload = shape(out, { fileName: row.original_name, bytes: buffer.length, analysisId });
    if (!includeText) delete payload.textPreview;
    res.json(payload);
  }));

  router.post('/upload', requireAuth, requirePermission('documents:analyze'), noStore, upload.single('file'), wrap(async (req, res) => {
    if (!req.file) throw badRequest('Aucun fichier reçu.');
    const maxBytes = Math.min(config.uploads.maxBytes, runtime.settings.number('files.max_upload_mb', 10) * 1024 * 1024);
    const keep = req.body?.keep !== '0';
    const buffer = req.file.buffer;
    const out = analyzeBuffer(buffer, classifyExtension(req.file.originalname).ext);
    let stored = null;
    if (keep) {
      stored = files.store({
        owner: req.user,
        originalName: req.file.originalname,
        mimeType: req.file.mimetype,
        buffer,
        maxBytes,
      }).file;
    }
    const analysisId = persist({
      actor: req.user,
      source: 'upload',
      extension: classifyExtension(req.file.originalname).ext,
      status: out.status,
      summary: out.summary,
      metrics: out.metrics,
      findings: out.findings,
      fileId: stored?.id ?? null,
    });
    audit.record({
      req,
      actor: req.user,
      action: audit.AUDIT.DOCUMENT_ANALYZED,
      category: 'agents',
      target_type: 'file',
      target_id: stored?.id ?? null,
      detail: { kind: out.kind, status: out.status, stored: Boolean(stored), findings: out.findings.length },
    });
    res.status(201).json({ ...shape(out, { fileName: req.file.originalname, bytes: buffer.length, analysisId }), stored });
  }));

  router.post('/inline', requireAuth, requirePermission('documents:analyze'), noStore, validateBody({
    content: S.text({ min: 1, max: 200000, label: 'contenu', multiline: true }),
    extension: S.text({ max: 8, required: false, default: '.txt', pattern: /^\.?[a-z0-9]{1,7}$/, patternHelp: 'extension type « .csv » ou « csv »' }),
  }), wrap(async (req, res) => {
    const { content, extension } = req.validated;
    const ext = extension.toLowerCase().startsWith('.') ? extension : `.${extension}`;
    if (!ANALYZABLE.has(ext)) throw unsupportedMedia(`Type non analysable (${ext}).`);
    if (Buffer.byteLength(content, 'utf8') > config.uploads.maxBytes) throw badRequest('Contenu trop volumineux.');
    const out = analyzeBuffer(Buffer.from(content, 'utf8'), ext);
    const analysisId = persist({
      actor: req.user,
      source: 'inline',
      extension: ext,
      status: out.status,
      summary: out.summary,
      metrics: out.metrics,
      findings: out.findings,
      fileId: null,
    });
    res.json({ ...shape(out, { fileName: `inline${ext}`, bytes: Buffer.byteLength(content, 'utf8'), analysisId }) });
  }));

  router.get('/', requireAuth, requirePermission('documents:analyze'), noStore, wrap(async (req, res) => {
    const { limit, offset } = pagination(req.query, { limit: 25, max: 100 });
    const all = rbac.can(req.user, 'files:read:any');
    const where = all ? '' : 'WHERE a.requested_by = ?';
    const params = all ? [] : [req.user.id];
    const total = db.get(`SELECT count(*) AS c FROM document_analyses a ${where}`, params).c;
    const rows = db.all(
      `SELECT a.*, f.original_name FROM document_analyses a LEFT JOIN files f ON f.id = a.file_id ${where} ORDER BY a.id DESC LIMIT ? OFFSET ?`,
      [...params, limit, offset],
    );
    res.json({
      total,
      items: rows.map((r) => ({
        id: r.id,
        fileId: r.file_id,
        fileName: r.original_name ?? `inline${r.extension}`,
        extension: r.extension,
        source: r.source,
        status: r.status,
        summary: r.summary,
        findings: safeJson(r.findings_json) ?? [],
        createdAt: r.created_at,
      })),
    });
  }));

  return router;
}

function readCapped(abs, maxBytes) {
  const stat = fs.statSync(abs);
  if (stat.size > maxBytes) throw badRequest('Fichier trop volumineux pour l’analyse.');
  return fs.readFileSync(abs);
}

function safeJson(s) {
  if (!s) return null;
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}

export { safeJson, utf8 };
export default createDocumentRoutes;
