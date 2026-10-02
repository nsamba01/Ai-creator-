/**
 * RBAC service — the single server-side authority for authorization.
 *
 * `requirePermission()` in the HTTP layer consults this service; nothing in
 * the React UI can widen a decision. Permission sets are resolved per user
 * (with a tiny request-scoped cache) and invalidated whenever a role or a
 * user-role assignment changes.
 */
import { logger } from '../utils/logger.js';
import { badRequest, notFound } from '../utils/errors.js';

export const ROLE_ADMIN = 'ADMIN';
export const ROLE_USER = 'USER';

/** Permissions that must never be granted to a non-ADMIN role. */
export const ADMIN_ONLY_PERMISSIONS = new Set([
  'users:create',
  'users:update',
  'users:delete',
  'users:disable',
  'users:reset_password',
  'roles:create',
  'roles:update',
  'roles:delete',
  'permissions:assign',
  'settings:update',
  'sessions:revoke:any',
  'files:delete:any',
  'files:read:any',
  'agents:update',
  'audit:export',
  'admin:access',
]);

export function createRbacService(db, { cacheTtlMs = 15_000 } = {}) {
  const cache = new Map();

  function resolvePermissions(userId) {
    const hit = cache.get(userId);
    if (hit && hit.expires > Date.now()) return hit.permissions;
    const rows = db.all(
      `SELECT DISTINCT p.key
         FROM user_roles ur
         JOIN role_permissions rp ON rp.role_id = ur.role_id
         JOIN permissions p ON p.id = rp.permission_id
        WHERE ur.user_id = ?`,
      [userId],
    );
    const permissions = new Set(rows.map((r) => r.key));
    cache.set(userId, { permissions, expires: Date.now() + cacheTtlMs });
    return permissions;
  }

  function resolveRoles(userId) {
    return db.all(`SELECT r.id, r.name, r.description, r.is_system FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = ? ORDER BY r.id`, [userId]);
  }

  return {
    invalidate(userId) {
      if (userId === undefined) cache.clear();
      else cache.delete(userId);
    },
    permissionsOf: resolvePermissions,
    rolesOf: resolveRoles,
    can(user, permission) {
      if (!user || !permission) return false;
      if (user.status !== 'active' && user.status !== 'pending_password') return false;
      if (permission.startsWith('users:self')) return Boolean(user);
      return resolvePermissions(user.id).has(permission);
    },
    canAny(user, permissions = []) {
      return permissions.some((p) => this.can(user, p));
    },
    canAll(user, permissions = []) {
      return permissions.every((p) => this.can(user, p));
    },
    listPermissions() {
      return db.all(`SELECT id, key, category, description, is_dangerous FROM permissions ORDER BY category, key`).map((r) => ({
        id: r.id,
        key: r.key,
        category: r.category,
        description: r.description,
        dangerous: Boolean(r.is_dangerous),
      }));
    },
    listRoles() {
      const roles = db.all(`SELECT id, name, description, is_system, created_at, updated_at FROM roles ORDER BY id`);
      return roles.map((role) => ({
        ...role,
        isSystem: Boolean(role.is_system),
        permissions: db.all(`SELECT p.key FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id WHERE rp.role_id = ? ORDER BY p.key`, [role.id]).map((r) => r.key),
        memberCount: db.get(`SELECT count(*) AS c FROM user_roles WHERE role_id = ?`, [role.id]).c,
      }));
    },
    roleByName(name) {
      return db.get(`SELECT id, name, description, is_system FROM roles WHERE name = ? COLLATE NOCASE`, [String(name)]);
    },
    permissionByKey(key) {
      return db.get(`SELECT id, key, category, is_dangerous FROM permissions WHERE key = ?`, [key]);
    },
    /** Assign roles, rejecting escalations the operator is not allowed to grant. */
    assignRoles({ actorUserId, userId, roleNames, allowAdminOnly = true }) {
      const wanted = [...new Set(roleNames.map((r) => String(r).trim()).filter(Boolean))];
      const roleRows = wanted.length
        ? db.all(`SELECT id, name FROM roles WHERE name IN (${wanted.map(() => '?').join(',')})`, wanted)
        : [];
      const found = new Set(roleRows.map((r) => r.name));
      const missing = wanted.filter((w) => !found.has(w.toUpperCase()) && !found.has(w));
      if (missing.length) {
        const err = badRequest(`Rôle inconnu : ${missing.join(', ')}.`, { unknown: missing });
        err.code = 'UNKNOWN_ROLE';
        throw err;
      }
      if (!allowAdminOnly) {
        const dangerousRoleIds = db.all(
          `SELECT DISTINCT rp.role_id AS id FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id WHERE p.key IN (${[...ADMIN_ONLY_PERMISSIONS].map(() => '?').join(',')})`,
          [...ADMIN_ONLY_PERMISSIONS],
        ).map((r) => r.id);
        const blocked = roleRows.filter((r) => dangerousRoleIds.includes(r.id));
        if (blocked.length) {
          const err = badRequest(`Rôle réservé aux administrateurs : ${blocked.map((b) => b.name).join(', ')}.`);
          err.code = 'ROLE_ESCALATION_BLOCKED';
          throw err;
        }
      }
      db.tx(() => {
        db.run(`DELETE FROM user_roles WHERE user_id = ?`, [userId]);
        for (const role of roleRows) {
          db.run(`INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_by) VALUES (?,?,?)`, [userId, role.id, actorUserId]);
        }
      });
      this.invalidate(userId);
      logger.debug('rôles assignés', { userId, roles: roleRows.map((r) => r.name) });
      return roleRows.map((r) => r.name);
    },
    setRolePermissions(roleId, permissionKeys) {
      const keys = [...new Set(permissionKeys.map((k) => String(k).trim()).filter(Boolean))];
      const rows = keys.length
        ? db.all(`SELECT id, key FROM permissions WHERE key IN (${keys.map(() => '?').join(',')})`, keys)
        : [];
      const known = new Set(rows.map((r) => r.key));
      const unknown = keys.filter((k) => !known.has(k));
      if (unknown.length) {
        const err = badRequest(`Permission inconnue : ${unknown.join(', ')}.`, { unknown });
        err.code = 'UNKNOWN_PERMISSION';
        throw err;
      }
      const role = db.get(`SELECT id, name FROM roles WHERE id = ?`, [roleId]);
      if (!role) throw notFound('Rôle introuvable.');
      db.tx(() => {
        db.run(`DELETE FROM role_permissions WHERE role_id = ?`, [roleId]);
        for (const p of rows) db.run(`INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?,?)`, [roleId, p.id]);
        db.run(`UPDATE roles SET updated_at = ? WHERE id = ?`, [new Date().toISOString(), roleId]);
      });
      // Everyone holding that role loses the cached view.
      this.invalidate();
      logger.warn('matrice de permissions modifiée', { roleId, roleName: role.name, granted: rows.length });
      return rows.length;
    },
    createRole(name, description = '') {
      const res = db.run(`INSERT INTO roles (name, description, is_system) VALUES (?, ?, 0)`, [String(name).trim(), description]);
      return db.get(`SELECT id, name, description, is_system FROM roles WHERE id = ?`, [res.lastInsertRowid]);
    },
    deleteRole(id) {
      const role = db.get(`SELECT id, name, is_system FROM roles WHERE id = ?`, [id]);
      if (!role) return { ok: false, reason: 'NOT_FOUND' };
      if (role.is_system) return { ok: false, reason: 'SYSTEM_ROLE' };
      db.run(`DELETE FROM roles WHERE id = ?`, [id]);
      this.invalidate();
      return { ok: true, name: role.name };
    },
  };
}

export default createRbacService;
