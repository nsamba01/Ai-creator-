/**
 * Typed application errors.
 *
 * Contract: `AppError expose()` is the ONLY shape allowed to reach a client.
 * It never carries stack traces, file paths, SQL fragments or secrets.
 */

export class AppError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.name = 'AppError';
    this.status = status;
    this.code = code;
    this.details = details;
    this.expose = true;
  }

  toJSON() {
    return {
      error: {
        code: this.code,
        message: this.message,
        ...(this.details ? { details: this.details } : {}),
      },
    };
  }
}

export const badRequest = (msg = 'Requête invalide.', details) =>
  new AppError(400, 'BAD_REQUEST', msg, details);

export const unauthorized = (msg = 'Authentification requise.') =>
  new AppError(401, 'UNAUTHENTICATED', msg);

export const forbidden = (msg = 'Accès refusé.', details) =>
  new AppError(403, 'FORBIDDEN', msg, details);

export const notFound = (msg = 'Ressource introuvable.') =>
  new AppError(404, 'NOT_FOUND', msg);

export const conflict = (msg = 'Conflit.', details) =>
  new AppError(409, 'CONFLICT', msg, details);

export const tooLarge = (msg = 'Contenu trop volumineux.') =>
  new AppError(413, 'PAYLOAD_TOO_LARGE', msg);

export const unsupportedMedia = (msg = 'Type de contenu non autorisé.') =>
  new AppError(415, 'UNSUPPORTED_MEDIA_TYPE', msg);

export const tooManyRequests = (msg = 'Trop de tentatives. Réessayez plus tard.', retryAfter) => {
  const err = new AppError(429, 'RATE_LIMITED', msg);
  err.retryAfter = retryAfter ?? 60;
  return err;
};

export const internal = (msg = 'Erreur interne du serveur.', cause) => {
  const err = new AppError(500, 'INTERNAL_ERROR', msg);
  if (cause) err.cause = cause;
  return err;
};

/** Normalises any thrown value into an AppError. */
export function toAppError(err, fallback = internal()) {
  if (err instanceof AppError) return err;
  if (err && typeof err.status === 'number' && err.status >= 400 && err.status < 600) {
    const e = new AppError(err.status, err.code ?? 'REQUEST_ERROR', err.expose === false ? fallback.message : (err.message || fallback.message));
    return e;
  }
  return fallback;
}
