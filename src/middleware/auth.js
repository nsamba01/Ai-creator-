/**
 * Authentication + authorization middlewares.
 *
 * `authenticate` attaches `req.user` / `req.permissions` from the session
 * cookie. `requireAuth`, `requirePermission` and `requireRoles` enforce the
 * decision server-side. A UI hiding a button is a UX detail, never a control.
 */
import { forbidden, unauthorized } from '../utils/errors.js';
import { COOKIE_NAMES, parseCookies } from '../utils/cookies.js';
import * as usersRepo from '../repositories/users.repo.js';
import { logger } from '../utils/logger.js';

export function createAuthMiddlewares(runtime) {
  const { config, auth, rbac, audit, db } = runtime;

  function readSessionToken(req) {
    const cookies = parseCookies(req.headers.cookie);
    if (cookies[COOKIE_NAMES.session]) return { token: cookies[COOKIE_NAMES.session], via: 'cookie' };
    const h = req.headers.authorization;
    if (typeof h === 'string' && /^Bearer\s+/i.test(h)) {
      // Bearer session tokens are accepted for API clients; cookies stay the
      // default for the SPA, so the CSRF rules apply to browsers.
      return { token: h.replace(/^Bearer\s+/i, '').trim(), via: 'bearer' };
    }
    return { token: null, via: null };
  }

  function authenticate(req, res, next) {
    try {
      // Test-only escape hatch, impossible to enable in production (see loadConfig).
      if (config.disableAuthForTests && req.headers['x-test-user-id']) {
        const userId = Number.parseInt(String(req.headers['x-test-user-id']), 10);
        const user = usersRepo.findUserById(db, userId, { withPermissions: true });
        if (user) {
          req.user = { ...user, permissions: [...rbac.permissionsOf(user.id)] };
          req.permissions = req.user.permissions;
          req.session = { id: 'test', user_id: user.id, csrf_token: 'test', expires_at: '9999' };
          return next();
        }
      }

      const { token, via } = readSessionToken(req);
      req.authVia = via;
      if (!token) return next();

      const resolved = auth.resolveSession(token);
      if (resolved?.revoked) {
        res.append('X-Session-State', resolved.reason);
        return next();
      }
      if (!resolved) return next();

      req.user = { ...resolved.user, permissions: [...rbac.permissionsOf(resolved.user.id)] };
      req.permissions = req.user.permissions;
      req.session = resolved.session;
      req.csrfToken = resolved.session.csrf_token;

      const lastSeen = new Date(resolved.session.last_seen_at).getTime();
      if (Date.now() - lastSeen > 30_000) runtime.touchSession(resolved.session.id);
      return next();
    } catch (err) {
      logger.warn('échec de résolution de session', { error: err.message });
      return next();
    }
  }

  function requireAuth(req, res, next) {
    if (!req.user) return next(unauthorized('Authentification requise.'));
    return next();
  }

  function requirePermission(...needed) {
    const keys = needed.flat().filter(Boolean);
    return function requirePermissionMiddleware(req, res, next) {
      if (!req.user) return next(unauthorized());
      if (req.user.mustChangePassword && !auth.PASSWORD_CHANGE_ALLOW_LIST.has(req.pathname)) {
        const err = forbidden('Changement du mot de passe initial requis avant d’utiliser cette fonctionnalité.');
        err.code = 'PASSWORD_CHANGE_REQUIRED';
        return next(err);
      }
      const granted = req.permissions ?? [...rbac.permissionsOf(req.user.id)];
      const missing = keys.filter((k) => !granted.includes(k));
      if (missing.length) {
        audit.record({
          req,
          actor: req.user,
          action: audit.AUDIT.AUTHZ_DENIED,
          category: 'security',
          outcome: 'blocked',
          severity: 'warning',
          targetType: 'permission',
          targetId: missing.join(','),
          detail: { method: req.method, path: req.pathname, missing },
        });
        return next(forbidden(`Permission manquante : ${missing.join(', ')}.`));
      }
      return next();
    };
  }

  function requireRoles(...roles) {
    const wanted = roles.flat().map((r) => String(r).toUpperCase());
    return (req, res, next) => {
      if (!req.user) return next(unauthorized());
      const userRoles = (req.user.roles ?? []).map((r) => String(r).toUpperCase());
      if (!wanted.some((r) => userRoles.includes(r))) return next(forbidden('Rôle insuffisant.'));
      return next();
    };
  }

  return { authenticate, requireAuth, requirePermission, requireRoles, readSessionToken };
}

export default createAuthMiddlewares;
