/**
 * Authentication service — the only place that may mint or destroy sessions.
 *
 * Guarantees (each covered by tests in tests/):
 *  - passwords verified against an Argon2id hash, never a plaintext value;
 *  - login throttling by IP+identifier and per-account lockout, both
 *    persisted (a restart cannot clear them);
 *  - session id rotation at login (anti session-fixation);
 *  - refresh-token rotation with reuse detection killing the whole family;
 *  - failed/successful authentications are audited without credentials;
 *  - `must_change_password` blocks every non-essential API call.
 */
import { hmacHex, randomHex, randomTempPassword, safeEqual } from '../utils/crypto.js';
import { AppError, badRequest, forbidden, internal, tooManyRequests, unauthorized } from '../utils/errors.js';
import { assertPasswordPolicy, hashPassword, verifyPassword } from './password.service.js';
import * as usersRepo from '../repositories/users.repo.js';
import * as sessionsRepo from '../repositories/sessions.repo.js';
import { logger } from '../utils/logger.js';

/** Endpoints that remain reachable while a forced password change is pending. */
export const PASSWORD_CHANGE_ALLOW_LIST = new Set([
  '/api/auth/logout',
  '/api/auth/me',
  '/api/auth/csrf',
  '/api/auth/change-password',
  '/api/meta',
  '/healthz',
  '/readyz',
]);

export function createAuthService({ db, config, audit, rbac, rateLimit }) {
  const sessionHash = (token) => hmacHex(config.sessionSecret, `s:${token}`);
  const refreshHash = (token) => hmacHex(config.sessionSecret, `r:${token}`);

  /** Resolves the session bound to a raw session token. */
  function resolveSession(rawToken) {
    if (!rawToken || typeof rawToken !== 'string' || rawToken.length < 16) return null;
    const row = sessionsRepo.findSessionByTokenHash(db, sessionHash(rawToken));
    if (!row) return null;
    if (row.revoked_at) return { revoked: true, reason: 'revoked' };
    if (new Date(row.expires_at).getTime() <= Date.now()) return { revoked: true, reason: 'expired' };
    const user = usersRepo.findUserById(db, row.user_id, { withPermissions: true });
    if (!user) return { revoked: true, reason: 'user_gone' };
    if (user.status === 'disabled' || user.status === 'deleted') return { revoked: true, reason: 'user_disabled' };
    return { user, session: row };
  }

  async function login({ identifier, password, ipHash, userAgentHash, userAgent }) {
    if (!identifier || !password) throw badRequest('Identifiant et mot de passe requis.');
    const bucket = `login:${ipHash ?? 'na'}|${String(identifier).toLowerCase().slice(0, 120)}`;
    const { maxAttempts, windowMs, lockMs } = {
      maxAttempts: config.lockout.maxAttempts,
      windowMs: config.lockout.windowMs,
      lockMs: config.lockout.lockMs,
    };

    const gate = rateLimit.consume(bucket, 1, { max: maxAttempts * 3, windowMs, blockMs: lockMs });
    if (!gate.allowed) {
      audit.record({ action: 'auth.login.throttled', category: 'auth', outcome: 'blocked', severity: 'warning', ipHash, detail: { identifier } });
      throw tooManyRequests('Trop de tentatives. Réessayez plus tard.', Math.ceil(gate.retryAfterMs / 1000));
    }

    const authRow = usersRepo.findAuthRowByIdentifier(db, identifier);
    // Uniform, deliberately slow failure so user enumeration stays unhelpful.
    const fail = async (message, extra = {}) => {
      if (authRow) {
        const { count, lockedUntil } = usersRepo.recordLoginFailure(db, authRow.id, { maxAttempts, lockMs });
        if (lockedUntil) {
          audit.record({
            action: audit.AUDIT.LOCKOUT,
            category: 'auth',
            outcome: 'blocked',
            severity: 'critical',
            actor: { id: authRow.id, email: authRow.email },
            ipHash,
            detail: { failedAttempts: count },
          });
        }
      }
      audit.record({
        action: audit.AUDIT.LOGIN_FAILURE,
        category: 'auth',
        outcome: 'failure',
        severity: 'notice',
        ipHash,
        userAgentHash,
        detail: { identifier, ...extra },
      });
      throw unauthorized(message);
    };

    if (!authRow) {
      // Consume a hash anyway: timing must not reveal account existence.
      await hashPassword('nonexistent-user-comparison-probe', config.password.argon2);
      return fail('Identifiant ou mot de passe incorrect.');
    }

    if (authRow.locked_until && new Date(authRow.locked_until).getTime() > Date.now()) {
      audit.record({
        action: audit.AUDIT.LOGIN_BLOCKED,
        category: 'auth',
        outcome: 'blocked',
        severity: 'warning',
        actor: { id: authRow.id, email: authRow.email },
        ipHash,
        detail: { reason: 'compte verrouillé' },
      });
      throw new AppError(423, 'ACCOUNT_LOCKED', 'Compte temporairement verrouillé après trop de tentatives.', {
        lockedUntil: authRow.locked_until,
      });
    }

    if (authRow.status === 'disabled' || authRow.status === 'deleted') {
      return fail('Compte désactivé.', { status: authRow.status });
    }

    const { ok, needsRehash } = await verifyPassword(password, authRow.password_hash, {
      memoryCost: config.password.argon2.memoryCost,
      timeCost: config.password.argon2.timeCost,
      parallelism: config.password.argon2.parallelism,
    });
    if (!ok) return fail('Identifiant ou mot de passe incorrect.');

    if (authRow.status === 'pending_password' && !authRow.must_change_password) {
      usersRepo.setUserStatus(db, authRow.id, 'active');
    }

    // ---- success -----------------------------------------------------------
    rateLimit.loginBucketReset(bucket);
    usersRepo.recordLoginSuccess(db, authRow.id);

    const actor = usersRepo.findUserById(db, authRow.id, { withPermissions: true });
    const user = actor;
    if (needsRehash) {
      const rehashed = await hashPassword(password, config.password.argon2);
      usersRepo.updatePassword(db, authRow.id, {
        passwordHash: rehashed.hash,
        hashParams: rehashed.params,
        clearMustChange: !authRow.must_change_password,
      });
      logger.info('empreinte obsolète recalculée', { userId: authRow.id });
    }

    const sessionToken = randomHex(32);
    const csrfToken = randomHex(16);
    const session = sessionsRepo.createSession(db, {
      userId: authRow.id,
      tokenHash: sessionHash(sessionToken),
      ttlMs: config.session.ttlMs,
      ipHash,
      userAgentHash,
      csrfToken,
    });
    const refreshToken = randomHex(48);
    const familyId = randomHex(12);
    sessionsRepo.issueRefreshToken(db, {
      userId: authRow.id,
      familyId,
      tokenHash: refreshHash(refreshToken),
      sessionId: session.id,
      ttlMs: config.session.refreshTtlMs,
    });

    audit.record({
      action: audit.AUDIT.LOGIN_SUCCESS,
      category: 'auth',
      actor: { id: actor.id, email: actor.email },
      ipHash,
      userAgentHash,
      detail: { roles: actor.roles },
    });

    return {
      user: { ...user, permissions: [...rbac.permissionsOf(actor.id)] },
      sessionToken,
      refreshToken,
      csrfToken,
      sessionId: session.id,
      expiresAt: session.expiresAt,
      mustChangePassword: Boolean(actor.mustChangePassword),
    };
  }

  function logout({ sessionRow, user }) {
    if (sessionRow?.id) {
      sessionsRepo.revokeSession(db, sessionRow.id, 'logout');
      sessionsRepo.revokeAllUserRefresh(db, sessionRow.user_id);
    }
    audit.record({ action: audit.AUDIT.LOGOUT, category: 'auth', actor: user ?? null, detail: null });
    return { ok: true };
  }

  /** Refresh-token rotation + reuse detection. */
  function refresh({ rawRefreshToken, ipHash, userAgentHash }) {
    if (!rawRefreshToken) throw unauthorized('Refresh token manquant.');
    const hash = refreshHash(rawRefreshToken);
    const row = sessionsRepo.findRefreshByHash(db, hash);
    if (!row) throw unauthorized('Refresh token invalide.');

    if (row.revoked_at || row.used_at) {
      // Reuse of a rotated token => assume theft: kill the whole family.
      sessionsRepo.revokeRefreshFamily(db, row.family_id, 'reuse_detected');
      sessionsRepo.revokeAllUserSessions(db, row.user_id, { reason: 'refresh_reuse' });
      audit.record({
        action: audit.AUDIT.REFRESH_REUSE_DETECTED,
        category: 'security',
        outcome: 'blocked',
        severity: 'critical',
        actor: { id: row.user_id, email: row.email },
        ipHash,
        userAgentHash,
        detail: { familyId: row.family_id },
      });
      logger.warn('réutilisation d’un refresh token détectée — famille révoquée', { userId: row.user_id });
      throw unauthorized('Refresh token révoqué.');
    }
    if (new Date(row.expires_at).getTime() <= Date.now()) throw unauthorized('Refresh token expiré.');

    const user = usersRepo.findUserById(db, row.user_id, { withPermissions: true });
    if (!user || user.status === 'disabled' || user.status === 'deleted') throw unauthorized('Compte indisponible.');

    const newRefresh = randomHex(48);
    const sessionToken = randomHex(32);
    const csrfToken = randomHex(16);
    const session = sessionsRepo.createSession(db, {
      userId: user.id,
      tokenHash: sessionHash(sessionToken),
      ttlMs: config.session.ttlMs,
      ipHash,
      userAgentHash,
      csrfToken,
    });
    const created = sessionsRepo.issueRefreshToken(db, {
      userId: user.id,
      familyId: row.family_id,
      tokenHash: refreshHash(newRefresh),
      sessionId: session.id,
      ttlMs: config.session.refreshTtlMs,
    });
    // Mark the old token consumed, linking it to its replacement.
    db.run(`UPDATE refresh_tokens SET used_at = ?, replaced_by = (SELECT id FROM refresh_tokens WHERE token_hash = ?) WHERE id = ?`, [
      new Date().toISOString(),
      created.tokenHash,
      row.id,
    ]);
    audit.record({ action: 'auth.refresh', category: 'auth', actor: { id: user.id, email: user.email }, ipHash, detail: null });

    return { user, sessionToken, refreshToken: newRefresh, csrfToken, expiresAt: session.expiresAt };
  }

  async function changePassword({ userId, currentPassword, newPassword, sessionRow, keepOnlyThisSession = true }) {
    const authRow = usersRepo.findAuthRowById(db, userId);
    if (!authRow) throw internal('Utilisateur introuvable.');

    if (currentPassword !== null) {
      const { ok } = await verifyPassword(String(currentPassword ?? ''), authRow.password_hash, config.password.argon2);
      if (!ok) throw unauthorized('Mot de passe actuel incorrect.');
    }
    assertPasswordPolicy(String(newPassword ?? ''), {
      minLength: config.password.minLength,
      context: [authRow.email, authRow.username],
    });
    const { hash, params } = await hashPassword(String(newPassword), config.password.argon2);
    usersRepo.updatePassword(db, userId, { passwordHash: hash, hashParams: params, clearMustChange: true });

    // Rotating the password invalidates every other session (stolen-cookie safety).
    sessionsRepo.revokeAllUserSessions(db, userId, {
      exceptId: keepOnlyThisSession ? sessionRow?.id ?? null : null,
      reason: 'password_changed',
    });
    sessionsRepo.revokeAllUserRefresh(db, userId);
    rbac.invalidate(userId);
    audit.record({
      action: audit.AUDIT.PASSWORD_CHANGED,
      category: 'auth',
      actor: { id: userId, email: authRow.email },
      target_type: 'user',
      target_id: userId,
      detail: { revokedOthers: true },
    });
    return { ok: true };
  }

  /** Admin-issued temporary password (never recoverable from the DB). */
  async function setTemporaryPassword({ userId, actorId, mustChange = true }) {
    const temp = randomTempPassword(16);
    assertPasswordPolicy(temp, { minLength: Math.min(12, config.password.minLength), context: [] });
    const { hash, params } = await hashPassword(temp, config.password.argon2);
    db.run(
      `UPDATE users SET password_hash = ?, hash_params = ?, must_change_password = ?, failed_login_attempts = 0,
              locked_until = NULL, status = 'active', password_changed_at = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`,
      [hash, JSON.stringify(params), mustChange ? 1 : 0, new Date().toISOString(), new Date().toISOString(), userId],
    );
    sessionsRepo.revokeAllUserSessions(db, userId, { reason: 'password_reset' });
    sessionsRepo.revokeAllUserRefresh(db, userId);
    audit.record({
      action: audit.AUDIT.USER_PASSWORD_RESET,
      category: 'admin',
      actor: { id: actorId },
      target_type: 'user',
      target_id: userId,
      severity: 'warning',
      detail: { mustChange, temporaryPasswordExposed: true },
    });
    return { temporaryPassword: temp, mustChange };
  }

  /** One-time reset token, stored as HMAC only. */
  function createResetToken({ userId, ttlMinutes = 30, createdBy = null, purpose = 'reset' }) {
    const raw = randomHex(32);
    const expiresAt = new Date(Date.now() + ttlMinutes * 60_000).toISOString();
    db.run(
      `INSERT INTO password_reset_tokens (user_id, token_hash, purpose, created_at, expires_at, created_by) VALUES (?,?,?,?,?,?)`,
      [userId, hmacHex(config.stateSecret, `p:${raw}`), purpose, new Date().toISOString(), expiresAt, createdBy],
    );
    return { raw, expiresAt };
  }

  function consumeResetToken(raw) {
    if (!raw) throw badRequest('Jeton requis.');
    const row = db.get(`SELECT * FROM password_reset_tokens WHERE token_hash = ?`, [hmacHex(config.stateSecret, `p:${raw}`)]);
    if (!row) throw badRequest('Jeton invalide.');
    if (row.used_at) throw badRequest('Jeton déjà utilisé.');
    if (new Date(row.expires_at).getTime() <= Date.now()) throw badRequest('Jeton expiré.');
    db.run(`UPDATE password_reset_tokens SET used_at = ? WHERE id = ?`, [new Date().toISOString(), row.id]);
    return { userId: row.user_id, purpose: row.purpose };
  }

  function assertPasswordChangeCompleted(user, path) {
    if (user?.mustChangePassword && !PASSWORD_CHANGE_ALLOW_LIST.has(path)) {
      throw new AppError(403, 'PASSWORD_CHANGE_REQUIRED', 'Le mot de passe initial doit être changé avant d’utiliser cette fonctionnalité.');
    }
  }

  function tokensMatch(a, b) {
    return safeEqual(a, b);
  }

  return {
    resolveSession,
    login,
    logout,
    refresh,
    changePassword,
    setTemporaryPassword,
    createResetToken,
    consumeResetToken,
    assertPasswordChangeCompleted,
    sessionHash,
    refreshHash,
    tokensMatch,
    PASSWORD_CHANGE_ALLOW_LIST,
  };
}

export default createAuthService;
