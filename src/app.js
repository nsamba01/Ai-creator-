/**
 * Express application assembly.
 *
 * Middleware order is a security decision, not an accident:
 *   1. request context (ids, anonymised IP)
 *   2. hardened headers (helmet + CSP + no-store on /api)
 *   3. CORS (exact origin allow-list, credentials, never `*`)
 *   4. body parsing with hard caps (multipart handled per-route by multer)
 *   5. global rate limit on /api
 *   6. authenticate (session -> req.user / req.permissions)
 *   7. forced password-change gate
 *   8. CSRF (needs the resolved session)
 *   9. API router, then the built SPA, then JSON 404, then the error handler
 */
import fs from 'node:fs';
import path from 'node:path';
import express from 'express';

import { createRequestContext } from './middleware/request-context.js';
import { createSecurityHeaders } from './middleware/security-headers.js';
import { createAuthMiddlewares } from './middleware/auth.js';
import { createCsrfMiddleware } from './middleware/csrf.js';
import { errorHandler, notFoundHandler } from './middleware/error-handler.js';
import { createApiRouter } from './routes/index.js';
import { createHealthRoutes } from './routes/health.routes.js';

export function createApp(runtime) {
  const { config, rateLimit, auth: authService } = runtime;
  const app = express();

  app.disable('x-powered-by');
  app.disable('etag');
  if (config.trustProxy) app.set('trust proxy', 1);
  app.locals.runtime = runtime;

  const middlewares = createAuthMiddlewares(runtime);
  runtime.middlewares = middlewares;

  app.use(createRequestContext(config));
  app.use(createSecurityHeaders(config));
  app.use(corsMiddleware(config));

  // Public probes first: cheap, no body, no cookies required.
  app.use('/', createHealthRoutes(runtime));

  app.use(
    '/api',
    express.json({
      limit: config.bodyLimit,
      strict: true,
      reviver: (key, value) => (typeof value === 'string' && value.length > 200000 ? undefined : value),
    }),
    express.urlencoded({ extended: false, limit: config.bodyLimit, parameterLimit: 40 }),
    globalRateLimit(runtime),
    middlewares.authenticate,
    passwordChangeGate(runtime),
    createCsrfMiddleware(runtime),
    createApiRouter(runtime),
  );

  app.use(...spaMiddleware(config));

  app.use(notFoundHandler);
  app.use(errorHandler(runtime));

  return app;
}

/** Exact-origin CORS. No wildcard, credentials only for allow-listed origins. */
function corsMiddleware(config) {
  return function cors(req, res, next) {
    const origin = req.headers.origin;
    if (origin) res.setHeader('Vary', 'Origin');
    if (origin && config.cors.allowedOrigins.has(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,PUT,DELETE,OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Accept,X-CSRF-Token,X-Request-Id');
      res.setHeader('Access-Control-Expose-Headers', 'X-Request-Id,X-Session-State,Content-Disposition');
      res.setHeader('Access-Control-Max-Age', '600');
    }
    if (req.method === 'OPTIONS') {
      res.statusCode = 204;
      return res.end();
    }
    return next();
  };
}

function globalRateLimit(runtime) {
  const { config } = runtime;
  return function rateLimitMiddleware(req, res, next) {
    if (config.disableAuthForTests) return next();
    const isAuthEndpoint = req.pathname.startsWith('/api/auth/');
    const bucket = isAuthEndpoint ? `api-auth:${req.ipHash}` : `api:${req.ipHash}`;
    const max = isAuthEndpoint ? config.limits.authPerMinute : config.limits.apiPerMinute;
    const out = runtime.rateLimit.consume(bucket, 1, {
      max,
      windowMs: 60_000,
      blockMs: 30_000,
    });
    res.setHeader('X-RateLimit-Limit', String(max));
    res.setHeader('X-RateLimit-Remaining', String(out.remaining));
    if (!out.allowed) {
      res.setHeader('Retry-After', String(Math.ceil(out.retryAfterMs / 1000)));
      return res.status(429).json({ error: { code: 'RATE_LIMITED', message: 'Trop de requêtes. Temporairement limité.' } });
    }
    return next();
  };
}

/**
 * Until the initial password is changed, the account may only reach a small
 * allow-list. Enforced here (all routes) rather than per-route, so a new
 * endpoint cannot accidentally be forgotten.
 */
function passwordChangeGate(runtime) {
  const allowList = runtime.auth.PASSWORD_CHANGE_ALLOW_LIST;
  return function gate(req, res, next) {
    if (!req.user?.mustChangePassword) return next();
    if (allowList.has(req.pathname)) return next();
    const err = new Error('Le mot de passe initial doit être changé avant d’accéder à cette fonctionnalité.');
    err.status = 403;
    err.code = 'PASSWORD_CHANGE_REQUIRED';
    return next(err);
  };
}

/**
 * Static SPA. `/assets/*` are content-hashed => immutable; index.html is never
 * cached so a deploy is immediately visible. Missing build => clear message
 * instead of a 500.
 */
function spaMiddleware(config) {
  const dist = path.join(config.root, 'dist');
  const indexPath = path.join(dist, 'index.html');
  const hasBuild = fs.existsSync(indexPath);

  return [
    ...(hasBuild
      ? [
          express.static(dist, {
            index: false,
            dotfiles: 'deny',
            etag: false,
            maxAge: 0,
            setHeaders(res, filePath) {
              if (filePath.includes(`${path.sep}assets${path.sep}`)) {
                res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
              } else {
                res.setHeader('Cache-Control', 'no-cache');
              }
            },
          }),
        ]
      : []),
    function serveSpa(req, res, next) {
      if (req.method !== 'GET' && req.method !== 'HEAD') return next();
      if (req.path.startsWith('/api/')) return next();
      if (!hasBuild) {
        return res
          .status(503)
          .type('text/plain; charset=utf-8')
          .send(
            'Interface web non construite. Lancez `npm run build` (ou laissez le stage 1 de l’image Docker le faire). L’API, elle, est opérationnelle.',
          );
      }
      // Only a whitelist of SPA routes may receive index.html; anything else is a 404.
      const allowed = /^\/(?:$|login|admin|dashboard|users|roles|sessions|audit|files|documents|urls|agents|settings|security|profile)(?:$|[/?#])/;
      if (!allowed.test(req.path) && !/\.(?:html|ico|webmanifest|txt|svg|png|css|js)$/.test(req.path)) {
        return res.status(404).type('text/plain; charset=utf-8').send('Page inconnue.');
      }
      const target = /\.(html|ico|svg|png|css|js|webmanifest)$/.test(req.path) ? path.join(dist, path.normalize(req.path)) : indexPath;
      if (target !== indexPath && !target.startsWith(dist + path.sep)) return res.status(400).send('Chemin refusé.');
      if (!fs.existsSync(target)) return res.status(404).type('text/plain; charset=utf-8').send('Page inconnue.');
      res.setHeader('Cache-Control', target === indexPath ? 'no-cache' : 'public, max-age=3600');
      return res.sendFile(target);
    },
  ];
}

export default createApp;
