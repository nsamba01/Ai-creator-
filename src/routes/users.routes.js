/**
 * User management routes.
 *
 * Authorization matrix (server-side, `requirePermission`):
 *   GET    /api/users              users:read
 *   POST   /api/users              users:create      <- a standard user cannot
 *   GET    /api/users/:id          users:read | self     create other users
 *   PATCH  /api/users/:id          users:update    | self (profile fields only)
 *   POST   /api/users/:id/roles    users:update
 *   POST   /api/users/:id/status   users:disable
 *   POST   /api/users/:id/reset-password users:reset_password
 *   DELETE /api/users/:id          users:delete
 *
 * Safety rails implemented here: no self-lockout, no removal of the last
 * administrator, sessions revoked whenever roles or status change.
 */
import { Router } from 'express';
import { wrap, noStore, pagination } from './_helpers.js';
import { validateBody, S } from '../middleware/validate.js';
import { badRequest, conflict, forbidden, notFound } from '../utils/errors.js';
import * as usersRepo from '../repositories/users.repo.js';
import * as sessionsRepo from '../repositories/sessions.repo.js';
import { hashPassword, assertPasswordPolicy } from '../services/password.service.js';
import { publicUser } from './auth.routes.js';
import { randomTempPassword } from '../utils/crypto.js';

export function createUserRoutes(runtime) {
  const router = Router();
  const { db, config, audit, rbac, auth, settings } = runtime;
  const { requireAuth, requirePermission } = runtime.middlewares;

  const roleNames = () => rbac.listRoles().map((r) => r.name);

  function isSelf(req, id) {
    return req.user && Number(id) === req.user.id;
  }

  function loadTarget(id) {
    const user = usersRepo.findUserById(db, Number(id));
    if (!user) throw notFound('Utilisateur introuvable.');
    return user;
  }

  /** A user may always read their own record; anything wider needs users:read. */
  /* ------------------------------ self-service ---------------------------- */
  const selfRouter = Router();
  selfRouter.get('/', requireAuth, noStore, wrap(async (req, res) => {
    const user = usersRepo.findUserById(db, req.user.id, { withPermissions: true });
    res.json({
      user: publicUser(user),
      permissions: [...rbac.permissionsOf(user.id)],
      roles: user.roles,
      security: {
        lastLoginAt: user.lastLoginAt,
        passwordChangedAt: user.passwordChangedAt,
        failedLoginAttempts: user.failedLoginAttempts,
        lockedUntil: user.lockedUntil,
        sessionsActive: db.get(`SELECT count(*) AS c FROM sessions WHERE user_id=? AND revoked_at IS NULL AND expires_at > ?`, [
          user.id,
          new Date().toISOString(),
        ]).c,
        policy: { minLength: settings.number('security.password_min_length', config.password.minLength) },
      },
    });
  }));

  selfRouter.patch('/', requireAuth, noStore, validateBody({
    displayName: S.text({ min: 1, max: 120, required: false, label: 'nom affiché' }),
    email: S.email({ required: false, label: 'e-mail' }),
    username: S.username({ required: false, label: 'identifiant' }),
  }), wrap(async (req, res) => {
    const { email, username, displayName } = req.validated;
    const clash = usersRepo.emailOrUsernameTaken(db, { email, username, exceptId: req.user.id });
    if (clash) throw conflict(`Cette ${clash === 'email' ? 'adresse e-mail' : 'identifiant'} est déjà utilisée.`);
    const user = usersRepo.setProfile(db, req.user.id, {
      email: email ?? req.user.email,
      username: username ?? req.user.username,
      displayName: displayName ?? req.user.displayName,
    });
    audit.record({ req, actor: req.user, action: 'user.profile.updated', category: 'users', target_type: 'user', target_id: req.user.id });
    res.json({ user: publicUser(user) });
  }));

  selfRouter.get('/events', requireAuth, noStore, wrap(async (req, res) => {
    const { limit, offset } = pagination(req.query, { limit: 25, max: 100 });
    res.json(audit.query({ actorId: req.user.id, limit, offset }));
  }));

  /* ------------------------------ admin scope ----------------------------- */
  router.get('/', requireAuth, requirePermission('users:read'), noStore, wrap(async (req, res) => {
    const { limit, offset } = pagination(req.query, { limit: 50, max: 200 });
    const q = String(req.query.q ?? '').slice(0, 120);
    const status = String(req.query.status ?? '').slice(0, 24);
    const out = usersRepo.listUsers(db, { q, status, limit, offset });
    res.json({
      ...out,
      roles: roleNames(),
      counts: {
        total: usersRepo.countUsers(db),
        admins: db.get(`SELECT count(*) AS c FROM users u JOIN user_roles ur ON ur.user_id=u.id JOIN roles r ON r.id=ur.role_id WHERE r.name='ADMIN' AND u.deleted_at IS NULL`).c,
      },
    });
  }));

  router.post(
    '/',
    requireAuth,
    noStore,
    validateBody({
      email: S.email({ label: 'e-mail' }),
      username: S.username({ label: 'identifiant' }),
      displayName: S.text({ min: 1, max: 120, required: false, label: 'nom affiché' }),
      roles: S.list({ required: false, maxItems: 10, label: 'rôles' }),
      password: S.password({ min: 8, max: 256, required: false, label: 'mot de passe temporaire' }),
      mustChangePassword: S.bool({ required: false, default: true }),
    }),
    requirePermission('users:create'),
    wrap(async (req, res) => {
      const { email, username, displayName, roles, password, mustChangePassword } = req.validated;
      if (usersRepo.emailOrUsernameTaken(db, { email, username })) {
        throw conflict('Cet e-mail ou cet identifiant existe déjà.');
      }
      const wantedRoles = (roles ?? ['USER']).map((r) => String(r).toUpperCase());
      // Only an operator holding every admin-only permission may mint an ADMIN.
      const grantsAdmin = wantedRoles.includes('ADMIN');
      if (grantsAdmin) {
        const actorPerms = rbac.permissionsOf(req.user.id);
        const needed = ['users:create', 'roles:update', 'admin:access'];
        if (!needed.every((p) => actorPerms.has(p))) {
          throw forbidden('Seul un administrateur complet peut attribuer le rôle ADMIN.');
        }
      }
      for (const r of wantedRoles) if (!roleNames().includes(r)) throw badRequest(`Rôle inconnu : ${r}`);

      let temporaryPassword = null;
      let plain = password;
      if (!plain) {
        temporaryPassword = randomTempPassword(16);
        plain = temporaryPassword;
      }
      assertPasswordPolicy(plain, {
        minLength: settings.number('security.password_min_length', config.password.minLength),
        context: [email, username],
      });
      const { hash, params } = await hashPassword(plain, config.password.argon2);

      const created = db.tx(() => {
        const user = usersRepo.createUser(db, {
          email,
          username,
          displayName: displayName ?? username,
          passwordHash: hash,
          hashParams: params,
          createdBy: req.user.id,
          mustChangePassword: password ? mustChangePassword !== false : true,
        });
        rbac.assignRoles({ actorUserId: req.user.id, userId: user.id, roleNames: wantedRoles });
        return user;
      });

      audit.record({
        req,
        actor: req.user,
        action: audit.AUDIT.USER_CREATED,
        category: 'admin',
        target_type: 'user',
        target_id: created.id,
        severity: 'notice',
        // Deliberately no password field: the audit service would drop it anyway.
        detail: { email: created.email, roles: wantedRoles, temporaryPasswordGenerated: Boolean(temporaryPassword), mustChangePassword: created.mustChangePassword },
      });

      res.status(201).json({
        user: publicUser(created),
        ...(temporaryPassword
          ? {
              temporaryPassword,
              warning: 'Mot de passe temporaire à transmettre hors bande (il ne sera plus jamais affiché et n’est pas récupérable depuis la base).',
            }
          : {}),
      });
    }),
  );

  router.get('/:id', requireAuth, noStore, wrap(async (req, res, next) => {
    const target = loadTarget(req.params.id);
    if (!isSelf(req, target.id) && !rbac.can(req.user, 'users:read')) throw forbidden('Permission users:read requise.');
    const detail = {
      ...target,
      sessions: sessionsRepo.listActiveSessions(db, { userId: target.id, limit: 20 }),
      recentEvents: rbac.can(req.user, 'audit:read') || isSelf(req, target.id) ? audit.query({ actorId: target.id, limit: 10 }).items : [],
      permissions: [...rbac.permissionsOf(target.id)],
    };
    res.json({ user: detail });
  }));

  router.patch(
    '/:id',
    requireAuth,
    noStore,
    validateBody({
      email: S.email({ required: false }),
      username: S.username({ required: false }),
      displayName: S.text({ min: 1, max: 120, required: false }),
      roles: S.list({ required: false, maxItems: 10 }),
      status: S.text({ required: false, enum: ['active', 'disabled', 'pending_password'], max: 24 }),
    }),
    wrap(async (req, res) => {
      const target = loadTarget(req.params.id);
      const self = isSelf(req, target.id);
      if (!self && !rbac.can(req.user, 'users:update')) throw forbidden('Permission users:update requise.');
      const changingRoles = req.validated.roles !== undefined;
      const changingIdentity = req.validated.email !== undefined || req.validated.username !== undefined;
      const changingStatus = req.validated.status !== undefined;
      if (self && (changingRoles || changingStatus)) throw forbidden('Un utilisateur ne peut pas modifier ses propres rôles ni son statut.');
      if (!self && !rbac.can(req.user, 'users:disable') && changingStatus) throw forbidden('Permission users:disable requise pour changer un statut.');

      const email = req.validated.email ?? target.email;
      const username = req.validated.username ?? target.username;
      if (email !== target.email || username !== target.username) {
        if (usersRepo.emailOrUsernameTaken(db, { email, username, exceptId: target.id })) throw conflict('E-mail ou identifiant déjà utilisé.');
        usersRepo.setProfile(db, target.id, { email, username, displayName: req.validated.displayName ?? target.displayName });
      } else if (req.validated.displayName) {
        usersRepo.setProfile(db, target.id, { email, username, displayName: req.validated.displayName });
      }

      if (changingRoles) {
        const wanted = req.validated.roles.map((r) => String(r).toUpperCase());
        if (wanted.includes('ADMIN')) {
          const actorPerms = rbac.permissionsOf(req.user.id);
          if (!['users:create', 'roles:update', 'admin:access'].every((p) => actorPerms.has(p))) {
            throw forbidden('Attribution du rôle ADMIN réservée à un administrateur complet.');
          }
        }
        if (wanted.length === 0) throw badRequest('Au moins un rôle est requis.');
        const removingAdminFromSelf = self && target.roles.includes('ADMIN') && !wanted.includes('ADMIN');
        if (removingAdminFromSelf) throw badRequest('Impossible de retirer votre propre rôle ADMIN.');
        if (target.roles.includes('ADMIN') && !wanted.includes('ADMIN') && usersRepo.countAdmins(db) <= 1) {
          throw conflict('Dernier administrateur : impossible de retirer le rôle.');
        }
        rbac.assignRoles({ actorUserId: req.user.id, userId: target.id, roleNames: wanted });
        // Privilege change => existing sessions must not keep old rights.
        sessionsRepo.revokeAllUserSessions(db, target.id, { reason: 'roles_changed' });
        sessionsRepo.revokeAllUserRefresh(db, target.id);
        rbac.invalidate(target.id);
      }

      if (changingStatus) {
        if (target.id === req.user.id && req.validated.status !== 'active') throw badRequest('Impossible de désactiver votre propre compte.');
        if (req.validated.status === 'disabled' && target.roles.includes('ADMIN') && usersRepo.countAdmins(db) <= 1) {
          throw conflict('Dernier administrateur actif : désactivation refusée.');
        }
        usersRepo.setUserStatus(db, target.id, req.validated.status);
        if (req.validated.status === 'disabled') {
          sessionsRepo.revokeAllUserSessions(db, target.id, { reason: 'account_disabled' });
          sessionsRepo.revokeAllUserRefresh(db, target.id);
        }
      }

      audit.record({
        req,
        actor: req.user,
        action: audit.AUDIT.USER_UPDATED,
        category: 'admin',
        target_type: 'user',
        target_id: target.id,
        detail: {
          rolesChanged: changingRoles,
          identityChanged: changingIdentity,
          statusChanged: changingStatus,
          newStatus: req.validated.status,
          self,
        },
      });
      res.json({ user: usersRepo.findUserById(db, target.id, { withPermissions: true }) });
    }),
  );

  router.post(
    '/:id/roles',
    requireAuth,
    noStore,
    validateBody({ roles: S.list({ maxItems: 10, label: 'rôles' }) }),
    requirePermission('users:update'),
    wrap(async (req, res) => {
      const target = loadTarget(req.params.id);
      const wanted = req.validated.roles.map((r) => String(r).toUpperCase());
      if (target.roles.includes('ADMIN') && !wanted.includes('ADMIN') && usersRepo.countAdmins(db) <= 1) {
        throw conflict('Dernier administrateur : impossible de retirer le rôle.');
      }
      const assigned = rbac.assignRoles({ actorUserId: req.user.id, userId: target.id, roleNames: wanted });
      sessionsRepo.revokeAllUserSessions(db, target.id, { reason: 'roles_changed' });
      rbac.invalidate(target.id);
      audit.record({
        req,
        actor: req.user,
        action: 'admin.user.roles_changed',
        category: 'admin',
        target_type: 'user',
        target_id: target.id,
        severity: 'warning',
        detail: { roles: assigned, previous: target.roles },
      });
      res.json({ user: usersRepo.findUserById(db, target.id, { withPermissions: true }) });
    }),
  );

  router.post(
    '/:id/status',
    requireAuth,
    noStore,
    validateBody({ status: S.text({ enum: ['active', 'disabled'], max: 24, label: 'statut' }), reason: S.text({ min: 3, max: 200, required: false }) }),
    requirePermission('users:disable'),
    wrap(async (req, res) => {
      const target = loadTarget(req.params.id);
      if (target.id === req.user.id) throw badRequest('Impossible de changer votre propre statut.');
      if (req.validated.status === 'disabled' && target.roles.includes('ADMIN') && usersRepo.countAdmins(db) <= 1) {
        throw conflict('Dernier administrateur actif : désactivation refusée.');
      }
      usersRepo.setUserStatus(db, target.id, req.validated.status);
      if (req.validated.status === 'disabled') {
        sessionsRepo.revokeAllUserSessions(db, target.id, { reason: 'account_disabled' });
        sessionsRepo.revokeAllUserRefresh(db, target.id);
      }
      audit.record({
        req,
        actor: req.user,
        action: req.validated.status === 'disabled' ? audit.AUDIT.USER_DISABLED : audit.AUDIT.USER_ENABLED,
        category: 'admin',
        severity: 'warning',
        target_type: 'user',
        target_id: target.id,
        detail: { reason: req.validated.reason ?? null },
      });
      res.json({ user: usersRepo.findUserById(db, target.id) });
    }),
  );

  router.post(
    '/:id/reset-password',
    requireAuth,
    noStore,
    validateBody({ mustChange: S.bool({ required: false, default: true }) }),
    requirePermission('users:reset_password'),
    wrap(async (req, res) => {
      const target = loadTarget(req.params.id);
      const { temporaryPassword } = await auth.setTemporaryPassword({
        userId: target.id,
        actorId: req.user.id,
        mustChange: req.validated.mustChange !== false,
      });
      res.status(201).json({
        temporaryPassword,
        mustChange: req.validated.mustChange !== false,
        message: 'Mot de passe temporaire généré. Il n’est stocké nulle part en clair et ne sera plus jamais affiché.',
      });
    }),
  );

  router.delete('/:id', requireAuth, noStore, requirePermission('users:delete'), wrap(async (req, res) => {
    const target = loadTarget(req.params.id);
    if (target.id === req.user.id) throw badRequest('Suppression de son propre compte interdite.');
    if (target.roles.includes('ADMIN') && usersRepo.countAdmins(db) <= 1) throw conflict('Dernier administrateur : suppression refusée.');
    db.tx(() => {
      sessionsRepo.revokeAllUserSessions(db, target.id, { reason: 'account_deleted' });
      sessionsRepo.revokeAllUserRefresh(db, target.id);
      usersRepo.softDeleteUser(db, target.id);
    });
    audit.record({ req, actor: req.user, action: audit.AUDIT.USER_DELETED, category: 'admin', severity: 'critical', target_type: 'user', target_id: target.id, detail: { email: target.email } });
    res.json({ ok: true, id: target.id, mode: 'logique (deleted_at)', recoverable: true });
  }));

  return { router, selfRouter };
}

export default createUserRoutes;
