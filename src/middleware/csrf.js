/**
 * CSRF protection: synchronous token pattern bound to the session row.
 *
 * Why both a cookie and a header:
 *  - the browser sends the `ps_csrf` cookie (readable by JS on purpose);
 *  - the SPA must echo it in `x-csrf-token`;
 *  - the server compares that value with the token stored in the *session row*,
 *    so a token leaked on another origin is useless.
 *
 * Safe methods and pre-auth routes are exempt (no session to abuse). Cookie
 * auth is `SameSite=Strict`, which is defence in depth, not the control.
 */
import { forbidden } from '../utils/errors.js';
import { COOKIE_NAMES, parseCookies } from '../utils/cookies.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export function createCsrfMiddleware(runtime) {
  const { config, audit } = runtime;

  return function csrfProtection(req, res, next) {
    if (!config.csrfEnabled) return next();
    if (SAFE_METHODS.has(req.method)) return next();
    // API clients using a Bearer token are not subject to ambient credential
    // attacks; browser cookie requests are.
    if (req.authVia === 'bearer') return next();
    const cookies = parseCookies(req.headers.cookie);
    const hasSessionCookie = Boolean(cookies[COOKIE_NAMES.session]);
    if (!hasSessionCookie || !req.user) return next();

    const header = String(req.headers['x-csrf-token'] ?? '').trim();
    const cookie = String(cookies[COOKIE_NAMES.csrf] ?? '').trim();
    const expected = String(req.csrfToken ?? '').trim();

    if (!header || !expected || header !== expected || cookie !== expected) {
      audit.record({
        req,
        actor: req.user,
        action: audit.AUDIT.CSRF_FAILURE,
        category: 'security',
        outcome: 'blocked',
        severity: 'warning',
        detail: { method: req.method, path: req.pathname, reason: header ? 'mismatch' : 'missing' },
      });
      const err = forbidden('Jeton CSRF absent ou invalide. Rechargez la page et réessayez.');
      err.code = 'CSRF_FAILURE';
      return next(err);
    }
    return next();
  };
}

export default createCsrfMiddleware;
