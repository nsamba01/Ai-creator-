/**
 * Roles & permissions administration.
 *
 * Two hard rails:
 *  - system roles (ADMIN/USER) cannot be deleted;
 *  - the ADMIN role can never lose the permissions needed to keep managing
 *    the platform (otherwise one click would lock everyone out).
 */
import { Router } from 'express';
import { wrap, noStore } from './_helpers.js';
import { validateBody, S } from '../middleware/validate.js';
import { badRequest, conflict, notFound } from '../utils/errors.js';

/** Permissions required to keep the ADMIN role operable. */
export const ADMIN_CORE_PERMISSIONS = [
  'admin:access',
  'users:read',
  'users:create',
  'users:update',
  'users:disable',
  'users:reset_password',
  'roles:read',
  'roles:update',
  'sessions:read:any',
  'sessions:revoke:any',
  'audit:read',
  'settings:read',
  'settings:update',
  'security:read',
];

export function createRbacRoutes(runtime) {
  const router = Router();
  const { db, audit, rbac } = runtime;
  const { requireAuth, requirePermission } = runtime.middlewares;

  router.get('/roles', requireAuth, requirePermission('roles:read'), noStore, wrap(async (req, res) => {
    res.json({ roles: rbac.listRoles() });
  }));

  router.get('/permissions', requireAuth, requirePermission('roles:read'), noStore, wrap(async (req, res) => {
    const permissions = rbac.listPermissions();
    const grouped = permissions.reduce((acc, p) => {
      (acc[p.category] ??= []).push(p);
      return acc;
    }, {});
    res.json({ permissions, grouped, adminOnly: [...new Set(permissions.filter((p) => p.dangerous).map((p) => p.key))] });
  }));

  router.post('/roles', requireAuth, requirePermission('roles:create'), noStore, validateBody({
    name: S.text({ min: 2, max: 32, pattern: /^[A-Z][A-Z0-9_]{1,31}$/, patternHelp: 'MAJUSCULES, chiffres et underscore', label: 'nom du rôle' }),
    description: S.text({ min: 3, max: 300, required: false, default: '' }),
    permissions: S.list({ required: false, maxItems: 200, lower: true }),
  }), wrap(async (req, res) => {
    const { name, description, permissions } = req.validated;
    if (rbac.roleByName(name)) throw conflict('Ce rôle existe déjà.');
    const created = rbac.createRole(name, description ?? '');
    if (permissions?.length) rbac.setRolePermissions(created.id, permissions);
    audit.record({ req, actor: req.user, action: audit.AUDIT.ROLE_CREATED, category: 'admin', target_type: 'role', target_id: created.id, detail: { name, granted: permissions?.length ?? 0 } });
    res.status(201).json({ role: { ...created, permissions: permissions ?? [] } });
  }));

  router.put('/roles/:id/permissions', requireAuth, requirePermission('roles:update'), noStore, validateBody({
    permissions: S.list({ maxItems: 200, label: 'permissions' }),
  }), wrap(async (req, res) => {
    const role = db.get(`SELECT id, name, is_system FROM roles WHERE id = ?`, [Number(req.params.id)]);
    if (!role) throw notFound('Rôle introuvable.');
    const wanted = req.validated.permissions.map((p) => String(p).toLowerCase());
    if (role.name === 'ADMIN') {
      const missing = ADMIN_CORE_PERMISSIONS.filter((p) => !wanted.includes(p));
      if (missing.length) {
        throw badRequest('Retirer ces permissions à ADMIN casserait l’administration.', { blocked: missing });
      }
    }
    // Anti-escalation: only a full administrator (admin:access) may grant
    // permissions they do not hold themselves, or edit the ADMIN role.
    const actorPerms = rbac.permissionsOf(req.user.id);
    const isFullAdmin = actorPerms.has('admin:access');
    if (!isFullAdmin) {
      if (role.name === 'ADMIN') throw forbiddenEscalation(['(édition du rôle ADMIN)']);
      const foreign = wanted.filter((p) => !actorPerms.has(p));
      if (foreign.length) throw forbiddenEscalation(foreign);
    }
    const granted = rbac.setRolePermissions(role.id, wanted);
    audit.record({
      req,
      actor: req.user,
      action: audit.AUDIT.ROLE_UPDATED,
      category: 'admin',
      severity: 'critical',
      target_type: 'role',
      target_id: role.id,
      detail: { role: role.name, granted, added: wanted.length },
    });
    res.json({ ok: true, role: rbac.listRoles().find((r) => r.id === role.id) });
  }));

  router.delete('/roles/:id', requireAuth, requirePermission('roles:delete'), noStore, wrap(async (req, res) => {
    const id = Number(req.params.id);
    const out = rbac.deleteRole(id);
    if (!out.ok) {
      if (out.reason === 'SYSTEM_ROLE') throw badRequest('Rôle système : suppression interdite.');
      throw notFound('Rôle introuvable.');
    }
    const members = db.get(`SELECT count(*) AS c FROM user_roles WHERE role_id = ?`, [id]).c;
    if (members) throw conflict('Des utilisateurs portent encore ce rôle.');
    audit.record({ req, actor: req.user, action: audit.AUDIT.ROLE_DELETED, category: 'admin', severity: 'critical', target_type: 'role', target_id: id, detail: { name: out.name } });
    res.json({ ok: true, deleted: out.name });
  }));

  return router;
}

function forbiddenEscalation(foreign) {
  const err = new Error(`Attribution refusée : vous ne détenez pas ${foreign.slice(0, 5).join(', ')}.`);
  err.status = 403;
  err.code = 'PERMISSION_ESCALATION_BLOCKED';
  return err;
}

export default createRbacRoutes;
