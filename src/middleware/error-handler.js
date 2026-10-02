/**
 * Terminal error handling.
 *
 * Guarantees:
 *  - clients get { error: { code, message } } — never a stack, an absolute
 *    path, a SQL fragment, or anything from `err.cause`;
 *  - full details (including cause) go to the structured server log only;
 *  - API 404 stays JSON, the SPA fallback returns index.html (see app.js).
 */
import { AppError, toAppError, internal, notFound } from '../utils/errors.js';
import { logger, redact } from '../utils/logger.js';

export function notFoundHandler(req, res, next) {
  if (req.path.startsWith('/api/')) return next(notFound(`Route inconnue : ${req.method} ${req.pathname}`));
  return next();
}

export function errorHandler(runtime) {
  const { config, audit } = runtime;
  return function handleApiError(err, req, res, next) {
    if (res.headersSent) return next(err);

    // multer size overflow and friends
    if (err?.code === 'LIMIT_FILE_SIZE') {
      err = new AppError(413, 'PAYLOAD_TOO_LARGE', `Fichier trop volumineux (maximum ${Math.round(config.uploads.maxBytes / 1024 / 1024)} Mo).`);
    }
    if (err?.type === 'entity.too.large') {
      err = new AppError(413, 'PAYLOAD_TOO_LARGE', 'Corps de requête trop volumineux.');
    }
    if (err?.type === 'entity.parse.failed') {
      err = new AppError(400, 'BAD_JSON', 'Corps JSON invalide.');
    }

    const appErr = toAppError(err, internal());
    const status = appErr.status;

    // Une 501 « non implémenté » ou une 503 de maintenance est une réponse **voulue** :
    // ce n'est pas une défaillance, et l'écrire au niveau error tromperait la surveillance.
    const deliberate = err instanceof AppError && (status === 501 || status === 503);
    if (status >= 500) {
      logger[deliberate ? 'warn' : 'error'](deliberate ? 'capacité annoncée indisponible' : 'erreur non gérée', {
        requestId: req.id,
        path: req.pathname,
        method: req.method,
        status,
        code: appErr.code,
        message: appErr.message,
        cause: appErr.cause ? redact(String(appErr.cause?.stack ?? appErr.cause?.message ?? appErr.cause)).slice(0, 800) : undefined,
      });
      if (!deliberate) {
        audit?.record?.({
          req,
          actor: req.user ?? null,
          action: 'system.error',
          category: 'system',
          outcome: 'error',
          severity: 'warning',
          detail: { code: appErr.code, status },
        });
      }
    } else if (status === 429 || status === 423) {
      logger.warn('accès refusé temporaires', { requestId: req.id, path: req.pathname, code: appErr.code });
    }

    res.status(status);
    if (appErr.retryAfter) res.setHeader('Retry-After', String(appErr.retryAfter));
    res.setHeader('Cache-Control', 'no-store');
    res.json({
      error: {
        code: appErr.code,
        message: status >= 500 && config.isProd ? 'Erreur interne du serveur.' : appErr.message,
        ...(appErr.details ? { details: appErr.details } : {}),
      },
      requestId: req.id ?? null,
    });
  };
}

export default errorHandler;
