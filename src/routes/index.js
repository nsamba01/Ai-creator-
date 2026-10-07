/**
 * API surface composition.
 *
 * Explicit middleware chain per mount:
 *   public            /api/auth/*, /healthz, /readyz, /api/meta
 *   authenticated     everything else (requireAuth)
 *   permission-gated  each route declares the permissions it needs
 *   maintenance       writes frozen for non-administrators
 *
 * The catch-all returns JSON 404 so unknown API paths never fall through to the
 * SPA (which would leak index.html and hide misconfiguration).
 */
import { Router } from 'express';
import { createHealthRoutes } from './health.routes.js';
import { createAuthRoutes } from './auth.routes.js';
import { createUserRoutes } from './users.routes.js';
import { createRbacRoutes } from './rbac.routes.js';
import { createSessionRoutes } from './sessions.routes.js';
import { createFileRoutes } from './files.routes.js';
import { createDocumentRoutes } from './documents.routes.js';
import { createUrlRoutes } from './urls.routes.js';
import { createAgentRoutes } from './agents.routes.js';
import { createVideoRoutes } from './videos.routes.js';
import { createAdminRoutes } from './admin.routes.js';
import { forbidden } from '../utils/errors.js';
import { wrap } from './_helpers.js';

export function maintenanceGuard(runtime) {
  return (req, res, next) => {
    if (req.method === 'GET' || req.method === 'HEAD') return next();
    if (!runtime.settings.bool('maintenance.mode', false)) return next();
    if (req.user && runtime.rbac.can(req.user, 'admin:access')) return next();
    return next(forbidden('Mode maintenance actif : seules les lectures et les administrateurs sont autorisées.'));
  };
}

export function createApiRouter(runtime) {
  const api = Router();
  const { requireAuth } = runtime.middlewares;

  const { router: authRouter } = createAuthRoutes(runtime);
  const { router: usersRouter, selfRouter } = createUserRoutes(runtime);

  api.use(maintenanceGuard(runtime));

  // Public
  api.use('/auth', authRouter);
  api.use('/', createHealthRoutes(runtime));

  // Authenticated / authorized
  api.use('/me', requireAuth, selfRouter);
  api.use('/users', requireAuth, usersRouter);
  api.use('/sessions', requireAuth, createSessionRoutes(runtime));
  api.use('/', createRbacRoutes(runtime));
  api.use('/files', requireAuth, createFileRoutes(runtime));
  api.use('/documents', requireAuth, createDocumentRoutes(runtime));
  api.use('/urls', requireAuth, createUrlRoutes(runtime));
  api.use('/agents', createAgentRoutes(runtime));
  api.use('/videos', requireAuth, createVideoRoutes(runtime));
  api.use('/admin', requireAuth, createAdminRoutes(runtime));

  api.get(
    '/heartbeat',
    requireAuth,
    wrap(async (req, res) => {
      res.json({ ok: true, at: new Date().toISOString(), mustChangePassword: Boolean(req.user.mustChangePassword) });
    }),
  );

  api.use((req, res) => {
    res.status(404).json({ error: { code: 'NOT_FOUND', message: `Route API inconnue : ${req.method} ${req.pathname}` } });
  });

  return api;
}

export default createApiRouter;
