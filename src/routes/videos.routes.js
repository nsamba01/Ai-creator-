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
 *   GET    /api/videos/:id/stream      lecture en continu Range (videos:stream, vidéo prête)
 *   HEAD   /api/videos/:id/stream      mêmes en-têtes, aucun octet
 *   POST   /api/videos/:id/jobs        mettre un job en file   (probe pour tous, kinds lourds : videos:process)
 *   GET    /api/videos/jobs            file portée             (videos:read)
 *   GET    /api/videos/jobs/:id        détail d'un job         (videos:read)
 *   POST   /api/videos/jobs/:id/cancel  annuler                 (propriétaire ou videos:manage-jobs)
 *   POST   /api/videos/jobs/:id/retry   remettre en file        (idem)
 *   POST   /api/videos/jobs/reap        ramasser les bails expirés (videos:manage-jobs)
 *   POST   /api/videos/from-url        501 assumé : la collecte par URL n'est pas ouverte
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
import fs from 'node:fs';

/** Clés connues, types connus : ce qui entre dans `input_json` de la file. */
function sanitizeJobInput(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const out = {};
  if (raw.format === 'png' || raw.format === 'wav') out.format = raw.format;
  for (const key of ['atMs', 'width', 'maxSeconds', 'maxKb']) {
    const n = Number(raw[key]);
    if (Number.isFinite(n)) out[key] = Math.max(0, Math.min(86_400_000, Math.trunc(n)));
  }
  return Object.keys(out).length ? out : null;
}

export function createVideoRoutes(runtime) {
  const router = Router();
  const { config, videos, files, videoJobs, videoStream, videoMedia } = runtime;
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
    const out = videos.register({ actor: req.user, fileId: req.validated.fileId });
    // `queued`/`job` ne sont pas du décoratif : en mode asynchrone l’actif est « pending », et sans
    // cette information le client croirait à un échec et relancerait des déclarations en boucle.
    res.status(out.created ? 201 : 200).json({
      asset: out.asset,
      task: out.task ?? null,
      alreadyRegistered: !out.created,
      queued: out.queued === true,
      job: out.job ?? null,
    });
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
    res.status(201).json({
      file: stored.file,
      duplicate: stored.duplicate,
      asset: out.asset,
      task: out.task ?? null,
      queued: out.queued === true,
      job: out.job ?? null,
    });
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
    const all = scopeAll(req);
    const out = videos.stats({ actor: req.user, scopeAll: all });
    res.json({
      ...out,
      streaming: videoStream.enabled(),
      // L'interface doit pouvoir dire « la vignette est possible ici » sans deviner : c'est le
      // serveur qui rend l'état du commutateur et de l'outil, pas une constante du client.
      tools: { enabled: videoMedia.toolsEnabled(), binary: Boolean(videoMedia.resolveBin()), limits: videoMedia.limits() },
      jobs: videoJobs.stats({ actor: req.user, scopeAll: all }),
    });
  }));

  router.post('/:id/jobs', requireAuth, noStore, validateBody({
    kind: { type: 'string', required: false, enum: ['probe', 'transcode', 'transcribe', 'thumbnail', 'moderation'], default: 'probe' },
    // Les paramètres d'une tâche voyagent avec elle, mais ne sont pas une saisie libre : liste
    // fermée de clés, types bornés. Le service re-borne de son côté (défense en profondeur).
    input: { type: 'object', required: false, keys: ['format', 'atMs', 'width', 'maxSeconds', 'maxKb'], enumPerKey: { format: ['png', 'wav'] }, maxKeys: 5 },
  }), wrap(async (req, res) => {
    const out = videoJobs.enqueue({ actor: req.user, videoId: Number(req.params.id), kind: req.validated.kind, input: sanitizeJobInput(req.validated.input) });
    res.status(202).json(out);
  }));

  router.get('/jobs', requireAuth, requirePermission('videos:read'), noStore, wrap(async (req, res) => {
    const { limit, offset } = pagination(req.query, { limit: 25, max: 100 });
    const all = scopeAll(req);
    const out = videoJobs.listFor({
      actor: req.user,
      videoId: req.query.videoId == null || req.query.videoId === '' ? null : Number(req.query.videoId),
      status: String(req.query.status ?? ''),
      scopeAll: all,
      limit,
      offset,
    });
    res.json({ scope: all ? 'all' : 'own', ...out });
  }));

  router.get('/jobs/stats', requireAuth, requirePermission('videos:read'), noStore, wrap(async (req, res) => {
    res.json(videoJobs.stats({ actor: req.user, scopeAll: Boolean(req.permissions?.includes('videos:read:any')) }));
  }));

  router.get('/jobs/:id', requireAuth, requirePermission('videos:read'), noStore, wrap(async (req, res) => {
    res.json({ job: videoJobs.get({ actor: req.user, id: Number(req.params.id), scopeAll: Boolean(req.permissions?.includes('videos:read:any')) }) });
  }));

  for (const action of ['cancel', 'retry']) {
    router.post(`/jobs/:id/${action}`, requireAuth, noStore, validateBody({}), wrap(async (req, res) => {
      res.json(videoJobs.act({ actor: req.user, id: Number(req.params.id), action }));
    }));
  }

  // Le ramassage est normalement fait par la boucle du worker. Cette route permet à un
  // administrateur de débloquer une file après un incident, sans redémarrage.
  router.post('/jobs/reap', requireAuth, requirePermission('videos:manage-jobs'), noStore, validateBody({
    purgeBefore: { type: 'string', required: false, max: 40, label: 'borne de purge' },
  }), wrap(async (req, res) => {
    // Le ramassage est un droit d'administration, pas une aubaine : la portée de la purge est
    // globale assumée, et l'acte est journalisé avec ses compteurs.
    res.json(videoJobs.reap({ actor: req.user, purgeBefore: req.validated.purgeBefore ?? null }));
  }));

  // La lecture en continu est la seule route du produit qui renvoie des octets de média :
  // elle est donc gardée par une permission dédiée, un réglage dédié, et refusée sur toute
  // vidéo qui n'est pas déclarée prête. Le corps est écrit par `fs.createReadStream` sur la
  // seule plage demandée — jamais par un readFile complet, ni par un chemin client.
  const streamHandler = wrap(async (req, res) => {
    const t = videoStream.target({
      id: Number(req.params.id),
      actor: req.user,
      scopeAll: Boolean(req.permissions?.includes('videos:read:any')),
      rangeHeader: req.headers.range ?? null,
      ifNoneMatch: req.headers['if-none-match'] ?? null,
    });
    for (const [k, v] of Object.entries(t.headers)) res.setHeader(k, v);
    if (t.notModified) {
      res.status(304).end();
      return;
    }
    if (t.unsatisfiable) {
      res.setHeader('Content-Range', `bytes */${t.size}`);
      res.status(416).end();
      return;
    }
    res.setHeader('ETag', t.etag);
    if (t.contentRange) res.setHeader('Content-Range', t.contentRange);
    res.status(t.status);
    if (req.method === 'HEAD') {
      res.end();
      return;
    }
    const stream = fs.createReadStream(t.abs, { start: t.start, end: t.end });
    let done = false;
    const close = () => {
      if (done) return;
      done = true;
      stream.destroy();
    };
    // Un lecteur qui part (seek, onglet fermé) ne doit pas laisser un descripteur ouvert.
    req.on('aborted', close);
    req.on('close', close);
    res.on('finish', () => {
      done = true;
    });
    stream.on('error', (err) => {
      if (res.headersSent) return res.destroy(err);
      res.status?.(500);
      return res.json?.({ error: { code: 'VIDEO_STREAM_FAILED', message: 'Lecture du média impossible.' } });
    });
    stream.pipe(res);
  });
  router.get('/:id/stream', requireAuth, requirePermission('videos:stream'), streamHandler);
  router.head('/:id/stream', requireAuth, requirePermission('videos:stream'), streamHandler);

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
