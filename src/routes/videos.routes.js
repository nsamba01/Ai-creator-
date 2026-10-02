/**
 * Routes de l'agent Vidéo (phase A).
 *
 * Surface exposée :
 *   POST   /api/videos                 déclarer un fichier déjà téléversé
 *   POST   /api/videos/upload          téléverser puis déclarer (une seule requête)
 *   GET    /api/videos                 liste portée (soi, ou tous avec videos:read:any)
 *   GET    /api/videos/stats           compteurs + posture de l'agent
 *   GET    /api/videos/:id             rapport de sondage + analyses
 *   POST   /api/videos/:id/probe       relancer un sondage
 *   POST   /api/videos/:id/quarantine  mettre en quarantaine   (videos:process)
 *   POST   /api/videos/:id/release     lever la quarantaine    (videos:process)
 *   POST   /api/videos/from-url        501 assumé : la collecte par URL est la phase B
 *
 * Rien ici ne décide d'une autorisation « à la main » en plus du garde-fou : les
 * permissions sont déclarées par route, et la portée (propriétaire) est re-vérifiée
 * dans le service — un identifiant devinable ne suffit jamais.
 */
import { Router } from 'express';
import multer from 'multer';
import { createUploadMiddleware } from '../middleware/upload.js';
import { wrap, noStore, pagination } from './_helpers.js';
import { validateBody, S } from '../middleware/validate.js';
import { badRequest, AppError } from '../utils/errors.js';
import { classifyExtension, FORBIDDEN_EXTENSIONS } from '../services/files.service.js';
import { VIDEO_ERRORS, VIDEO_EXTENSIONS } from '../services/video.service.js';

export function createVideoRoutes(runtime) {
  const router = Router();
  const { config, videos, files } = runtime;
  const { requireAuth, requirePermission } = runtime.middlewares;

  // Le plafond annoncé à multer est celui qui sera réellement appliqué : sans ça, un client
  // pourrait faire entrer 10 Mo en mémoire pour une vidéo plafonnée à 2 Mo — gaz
  // à effets de bord dans `maxBytes`, et message d’erreur qui ment sur la limite en vigueur.
  const videoCap = Math.min(config.uploads.maxBytes, videos.limits().maxBytes);
  const upload = createUploadMiddleware(
    multer({
      storage: multer.memoryStorage(),
      preservePath: false,
      limits: { fileSize: videoCap, files: 1, fields: 1, fieldSize: 512 },
      fileFilter(req, file, cb) {
        const { ext } = classifyExtension(file.originalname);
        if (FORBIDDEN_EXTENSIONS.has(ext)) {
          const err = badRequest(`Extension refusée (${ext}).`);
          err.code = 'FILE_TYPE_REFUSED';
          return cb(err);
        }
        if (!VIDEO_EXTENSIONS.has(ext)) {
          const err = new AppError(415, VIDEO_ERRORS.UNSUPPORTED_CONTAINER, `Conteneur vidéo non pris en charge (${ext || 'extension absente'}).`);
          return cb(err);
        }
        cb(null, true);
      },
    }),
    config,
  );

  const scopeAll = (req) => req.permissions?.includes('videos:read:any');

  router.post('/', requireAuth, requirePermission('videos:upload'), noStore, validateBody({
    fileId: S.id({ label: 'identifiant de fichier' }),
  }), wrap(async (req, res) => {
    const { asset, created, task } = videos.register({ actor: req.user, fileId: req.validated.fileId });
    res.status(created ? 201 : 200).json({ asset, task: task ?? null, alreadyRegistered: !created });
  }));

  router.post('/upload', requireAuth, requirePermission('files:create'), requirePermission('videos:upload'), noStore, upload.single('file'), wrap(async (req, res) => {
    if (!req.file) throw badRequest('Aucun fichier reçu.');
    const maxBytes = videoCap;
    const stored = files.store({
      owner: req.user,
      originalName: req.file.originalname,
      mimeType: req.file.mimetype,
      buffer: req.file.buffer,
      maxBytes,
    });
    const out = videos.register({ actor: req.user, fileId: stored.file.id });
    res.status(201).json({ file: stored.file, duplicate: stored.duplicate, asset: out.asset, task: out.task ?? null });
  }));

  router.post('/from-url', requireAuth, requirePermission('videos:upload'), noStore, validateBody({
    url: S.text({ max: 2000, label: 'url' }),
  }), wrap(async (req, res) => {
    // Réponse explicite plutôt qu'un 404 : la collecte réseau d'un média est une
    // fonction à part (téléchargement borné + SSRF + reprise), pas un détail.
    throw new AppError(
      501,
      VIDEO_ERRORS.URL_NOT_IMPLEMENTED,
      "La déclaration d'une vidéo par URL n'est pas implémentée (phase B du chantier) : téléversez le fichier, puis déclarez-le par son identifiant.",
    );
  }));

  router.get('/', requireAuth, requirePermission('videos:read'), noStore, wrap(async (req, res) => {
    const { limit, offset } = pagination(req.query, { limit: 25, max: 100 });
    const all = scopeAll(req);
    const out = videos.list({
      actor: req.user,
      scopeAll: all,
      status: String(req.query.status ?? ''),
      q: String(req.query.q ?? ''),
      limit,
      offset,
    });
    res.json({ scope: all ? 'all' : 'own', ...out });
  }));

  router.get('/stats', requireAuth, requirePermission('videos:read'), noStore, wrap(async (req, res) => {
    res.json(videos.stats({ actor: req.user, scopeAll: scopeAll(req) }));
  }));

  router.get('/:id', requireAuth, requirePermission('videos:read'), noStore, wrap(async (req, res) => {
    res.json(videos.get({ id: Number(req.params.id), actor: req.user, scopeAll: scopeAll(req) }));
  }));

  router.post('/:id/probe', requireAuth, noStore, validateBody({}), wrap(async (req, res) => {
    // Relancer son propre sondage est sans risque (lecture seule du fichier) ;
    // sortir de la quarantaine demande la permission de traitement.
    const needsProcess = req.permissions?.includes('videos:process');
    if (!req.permissions?.includes('videos:upload') && !needsProcess) {
      throw new AppError(403, 'AUTHZ_DENIED', 'Permission requise : videos:upload.');
    }
    const out = videos.reprobe({ id: Number(req.params.id), actor: req.user });
    res.json(out);
  }));

  router.post('/:id/quarantine', requireAuth, requirePermission('videos:process'), noStore, wrap(async (req, res) => {
    res.json({ asset: videos.setQuarantine({ id: Number(req.params.id), actor: req.user, quarantined: true }) });
  }));

  router.post('/:id/release', requireAuth, requirePermission('videos:process'), noStore, wrap(async (req, res) => {
    res.json({ asset: videos.setQuarantine({ id: Number(req.params.id), actor: req.user, quarantined: false }) });
  }));

  return router;
}

export default createVideoRoutes;
export { VIDEO_ERRORS };
