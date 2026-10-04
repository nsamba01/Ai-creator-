/**
 * Authentication routes.
 *
 * Contract with the SPA:
 *  - session + refresh tokens live in HttpOnly cookies only (never in
 *    localStorage, never in a response body);
 *  - the CSRF token is returned in the body and mirrored in a JS-readable
 *    cookie; it is bound to the session row on the server;
 *  - responses never contain password material, hashes or raw tokens.
 */
import { Router } from 'express';
import { wrap, noStore } from './_helpers.js';
import { COOKIE_NAMES, serializeCookie, clearCookie } from '../utils/cookies.js';
import { validateBody, S } from '../middleware/validate.js';
import { badRequest, unauthorized, forbidden } from '../utils/errors.js';
import * as usersRepo from '../repositories/users.repo.js';
import * as sessionsRepo from '../repositories/sessions.repo.js';
import { hashPassword } from '../services/password.service.js';

export function createAuthRoutes(runtime) {
  const router = Router();
  const { config, auth, db, audit, rbac, rateLimit, settings, middlewares } = runtime;
  const { requireAuth } = middlewares;

  const cookieBase = {
    path: '/',
    secure: config.cookies.secure,
    sameSite: config.cookies.sameSite === 'strict' ? 'Strict' : config.cookies.sameSite === 'lax' ? 'Lax' : 'None',
    maxAge: Math.floor(config.session.ttlMs / 1000),
  };
  const refreshCookie = { ...cookieBase, maxAge: Math.floor(config.session.refreshTtlMs / 1000), path: '/api/auth' };

  function setAuthCookies(res, { sessionToken, refreshToken, csrfToken, expiresAt }) {
    const chips = config.cookies.prefix && config.cookies.secure ? '__Host-' : '';
    const headers = [
      serializeCookie(`${chips}${COOKIE_NAMES.session}`, sessionToken, { ...cookieBase, httpOnly: true, expires: expiresAt }),
      serializeCookie(`${chips}${COOKIE_NAMES.refresh}`, refreshToken, { ...refreshCookie, httpOnly: true }),
      serializeCookie(`${chips}${COOKIE_NAMES.csrf}`, csrfToken, { ...cookieBase, httpOnly: false }),
    ];
    if (chips) headers.push(clearCookie(COOKIE_NAMES.session, cookieBase), clearCookie(COOKIE_NAMES.csrf, cookieBase));
    res.setHeader('Set-Cookie', headers);
    res.locals.csrfToken = csrfToken;
  }

  function clearAuthCookies(res) {
    const chips = config.cookies.prefix && config.cookies.secure ? '__Host-' : '';
    res.setHeader('Set-Cookie', [
      clearCookie(`${chips}${COOKIE_NAMES.session}`, cookieBase),
      clearCookie(`${chips}${COOKIE_NAMES.refresh}`, refreshCookie),
      clearCookie(`${chips}${COOKIE_NAMES.csrf}`, cookieBase),
      clearCookie(COOKIE_NAMES.session, cookieBase),
      clearCookie(COOKIE_NAMES.refresh, refreshCookie),
      clearCookie(COOKIE_NAMES.csrf, cookieBase),
    ]);
  }

  /** Public: lets the login screen mirror the server-side policy. */
  router.get('/status', noStore, (req, res) => {
    res.json({
      ok: true,
      csrfEnabled: config.csrfEnabled,
      cookieSecure: config.cookies.secure,
      sameSite: config.cookies.sameSite,
      policy: {
        passwordMinLength: settings.number('security.password_min_length', config.password.minLength),
        loginMaxAttempts: settings.number('security.login_max_attempts', config.lockout.maxAttempts),
        sessionTtlMinutes: settings.number('security.session_ttl_minutes', Math.round(config.session.ttlMs / 60000)),
        selfRegistration: settings.bool('auth.self_registration', false),
      },
      hashing: { algorithm: 'argon2id', plaintextStored: false },
    });
  });

  /** Session-bound CSRF token for the SPA. */
  router.get(
    '/csrf',
    wrap(async (req, res) => {
      if (!req.user) throw unauthorized('Authentification requise pour obtenir un jeton CSRF.');
      res.json({ csrfToken: req.csrfToken, header: 'x-csrf-token' });
    }),
  );

  router.post(
    '/login',
    noStore,
    validateBody({
      identifier: S.text({ min: 2, max: 320, required: true, label: 'identifiant' }),
      password: S.password({ min: 1, max: 256, label: 'mot de passe' }),
    }),
    wrap(async (req, res) => {
      const { identifier, password } = req.validated;
      const result = await auth.login({
        identifier,
        password,
        ipHash: req.ipHash,
        userAgentHash: req.uaHash,
        userAgent: req.userAgent,
      });
      setAuthCookies(res, result);
      res.json({
        user: publicUser(result.user),
        csrfToken: result.csrfToken,
        mustChangePassword: result.mustChangePassword,
        expiresAt: result.expiresAt,
      });
    }),
  );

  router.post(
    '/logout',
    noStore,
    wrap(async (req, res) => {
      if (req.user) auth.logout({ sessionRow: req.session, user: req.user });
      clearAuthCookies(res);
      res.json({ ok: true, message: 'Déconnecté.' });
    }),
  );

  router.post(
    '/refresh',
    noStore,
    wrap(async (req, res) => {
      const gate = rateLimit.consume(`refresh:${req.ipHash}`, 1, { max: 30, windowMs: 60_000, blockMs: 120_000 });
      if (!gate.allowed) throw badRequest('Trop de rafraîchissements. Réessayez dans quelques instants.');
      const cookieValue = parseCookieValue(req, COOKIE_NAMES.refresh);
      const raw = cookieValue ?? (typeof req.body?.refreshToken === 'string' ? req.body.refreshToken.slice(0, 200) : null);
      if (!raw) {
        clearAuthCookies(res);
        throw unauthorized('Aucun jeton de rafraîchissement.');
      }
      const out = auth.refresh({ rawRefreshToken: raw, ipHash: req.ipHash, userAgentHash: req.uaHash });
      setAuthCookies(res, out);
      res.json({ user: publicUser(out.user), csrfToken: out.csrfToken, expiresAt: out.expiresAt });
    }),
  );

  router.get(
    '/me',
    noStore,
    wrap(async (req, res) => {
      if (!req.user) throw unauthorized('Aucune session active.');
      res.json({ user: publicUser(req.user), permissions: [...rbac.permissionsOf(req.user.id)], mustChangePassword: Boolean(req.user.mustChangePassword) });
    }),
  );

  router.post(
    '/change-password',
    // requireAuth is mandatory here: the handler reads req.user.id. Without it,
    // an anonymous call used to reach the service and surface as a 500 instead of
    // a clean 401 (no state is ever changed, but the contract must be explicit).
    requireAuth,
    noStore,
    validateBody({
      currentPassword: S.password({ min: 1, max: 256, label: 'mot de passe actuel' }),
      newPassword: S.password({ min: Math.min(8, config.password.minLength), max: 256, label: 'nouveau mot de passe' }),
      confirm: S.text({ min: 1, max: 256, required: false, label: 'confirmation' }),
    }),
    wrap(async (req, res) => {
      const { currentPassword, newPassword, confirm } = req.validated;
      if (confirm !== undefined && confirm !== newPassword) throw badRequest('La confirmation ne correspond pas au nouveau mot de passe.');
      if (currentPassword === newPassword) throw badRequest('Le nouveau mot de passe doit être différent de l’ancien.');
      await auth.changePassword({ userId: req.user.id, currentPassword, newPassword, sessionRow: req.session });
      // Rebind a fresh session + CSRF token so the old cookie is useless.
      const user = usersRepo.findUserById(db, req.user.id, { withPermissions: true });
      res.json({ ok: true, message: 'Mot de passe mis à jour. Toutes les autres sessions ont été révoquées.', user: publicUser(user) });
    }),
  );

  /**
   * Recovery: never discloses whether the account exists. The reset link is
   * delivered by the configured notification channel; in development only the
   * token is echoed back to make the flow testable.
   */
  router.post(
    '/password-reset/request',
    noStore,
    validateBody({ identifier: S.text({ min: 2, max: 320, label: 'identifiant' }) }),
    wrap(async (req, res) => {
      const { identifier } = req.validated;
      const row = usersRepo.findAuthRowByIdentifier(db, identifier);
      let devToken = null;
      if (row && row.status !== 'deleted') {
        const { raw } = auth.createResetToken({ userId: row.id, ttlMinutes: 30, createdBy: null, purpose: 'reset' });
        audit.record({
          req,
          action: audit.AUDIT.PASSWORD_RESET_ISSUED,
          category: 'auth',
          actor: { id: row.id, email: row.email },
          target_type: 'user',
          target_id: row.id,
          detail: { ttlMinutes: 30 },
        });
        if (!config.isProd) devToken = raw;
      }
      res.status(202).json({
        accepted: true,
        message: 'Si ce compte existe, une procédure de réinitialisation vient d’être envoyée.',
        ...(devToken ? { devToken, note: 'Visible hors production : à ne jamais exposer publiquement.' } : {}),
      });
    }),
  );

  router.post(
    '/password-reset/confirm',
    noStore,
    validateBody({
      token: S.text({ min: 16, max: 200, label: 'jeton' }),
      newPassword: S.password({ min: Math.min(8, config.password.minLength), max: 256, label: 'nouveau mot de passe' }),
    }),
    wrap(async (req, res) => {
      const { token, newPassword } = req.validated;
      const { userId } = auth.consumeResetToken(token);
      const policyMin = settings.number('security.password_min_length', config.password.minLength);
      const { assertPasswordPolicy } = await import('../services/password.service.js');
      assertPasswordPolicy(newPassword, { minLength: policyMin, context: [] });
      const { hash, params } = await hashPassword(newPassword, config.password.argon2);
      usersRepo.updatePassword(db, userId, { passwordHash: hash, hashParams: params, clearMustChange: true });
      // A reset must invalidate everything: sessions and refresh tokens.
      const revokedSessions = sessionsRepo.revokeAllUserSessions(db, userId, { reason: 'password_reset' });
      sessionsRepo.revokeAllUserRefresh(db, userId);
      rbac.invalidate(userId);
      audit.record({
        req,
        action: audit.AUDIT.PASSWORD_RESET_CONSUMED,
        category: 'auth',
        actor: { id: userId },
        target_type: 'user',
        target_id: userId,
        severity: 'warning',
        detail: { revokedSessions },
      });
      clearAuthCookies(res);
      res.json({ ok: true, message: 'Mot de passe réinitialisé. Reconnectez-vous.', revokedSessions });
    }),
  );

  return { router, clearAuthCookies, setAuthCookies, publicUser };
}

function parseCookieValue(req, name) {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const part of String(header).split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === name || part.slice(0, idx).trim() === `__Host-${name}`) {
      try {
        return decodeURIComponent(part.slice(idx + 1).trim());
      } catch {
        return part.slice(idx + 1).trim();
      }
    }
  }
  return null;
}

export function publicUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    email: user.email,
    username: user.username,
    displayName: user.displayName || user.username,
    status: user.status,
    roles: user.roles ?? [],
    permissions: user.permissions ?? [],
    mustChangePassword: Boolean(user.mustChangePassword),
    lastLoginAt: user.lastLoginAt ?? null,
    passwordChangedAt: user.passwordChangedAt ?? null,
    createdAt: user.createdAt ?? null,
  };
}

export default createAuthRoutes;
