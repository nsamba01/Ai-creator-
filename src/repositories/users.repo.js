/**
 * Users repository.
 *
 * Security invariants:
 *  - `password_hash` / `hash_params` are selected by dedicated internal
 *    functions only and are stripped by `toPublic()` before any response;
 *  - every query is fully parameterised.
 */

const PUBLIC_SELECT = `
  u.id, u.email, u.username, u.display_name, u.status, u.must_change_password,
  u.failed_login_attempts, u.locked_until, u.last_login_at, u.password_changed_at,
  u.created_at, u.updated_at, u.created_by, u.deleted_at
`;

/** Role names are joined in the same query to avoid N+1 on list endpoints. */
const ROLES_SUBQUERY = `(SELECT group_concat(r.name, ',') FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = u.id) AS role_names`;

export function toPublic(row) {
  if (!row) return undefined;
  return {
    id: row.id,
    email: row.email,
    username: row.username,
    displayName: row.display_name || row.username,
    status: row.status,
    mustChangePassword: Boolean(row.must_change_password),
    failedLoginAttempts: row.failed_login_attempts ?? 0,
    lockedUntil: row.locked_until ?? null,
    lastLoginAt: row.last_login_at ?? null,
    passwordChangedAt: row.password_changed_at ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    createdBy: row.created_by ?? null,
    deletedAt: row.deleted_at ?? null,
    roles: row.role_names ? String(row.role_names).split(',').filter(Boolean) : [],
    permissions: row.permissions ?? undefined,
  };
}

export function findUserById(db, id, { withPermissions = false } = {}) {
  const permCols = withPermissions
    ? `, (SELECT group_concat(p.key, ',') FROM user_roles ur2
            JOIN role_permissions rp ON rp.role_id = ur2.role_id
            JOIN permissions p ON p.id = rp.permission_id
           WHERE ur2.user_id = u.id) AS permissions`
    : '';
  const row = db.get(
    `SELECT ${PUBLIC_SELECT}, ${ROLES_SUBQUERY}${permCols} FROM users u WHERE u.id = ? AND u.deleted_at IS NULL`,
    [id],
  );
  return toPublic(row);
}

export function findUserByIdentifier(db, identifier, { withPermissions = false } = {}) {
  const permCols = withPermissions
    ? `, (SELECT group_concat(p.key, ',') FROM user_roles ur2
            JOIN role_permissions rp ON rp.role_id = ur2.role_id
            JOIN permissions p ON p.id = rp.permission_id
           WHERE ur2.user_id = u.id) AS permissions`
    : '';
  const value = String(identifier ?? '').trim();
  if (!value) return undefined;
  const row = db.get(
    `SELECT ${PUBLIC_SELECT}, ${ROLES_SUBQUERY}${permCols}
       FROM users u
      WHERE (lower(u.email) = lower(?) OR u.username = ?) AND u.deleted_at IS NULL
      LIMIT 1`,
    [value, value],
  );
  return row ? withPermissions ? { ...toPublic(row), permissions: String(row.permissions ?? '').split(',').filter(Boolean) } : toPublic(row) : undefined;
}

/** Raw row including the hash — internal use only (login / password change). */
export function findAuthRowByIdentifier(db, identifier) {
  const value = String(identifier ?? '').trim();
  if (!value) return undefined;
  return db.get(
    `SELECT id, email, username, password_hash, hash_params, status, must_change_password,
            failed_login_attempts, locked_until
       FROM users
      WHERE (lower(email) = lower(?) OR username = ?) AND deleted_at IS NULL
      LIMIT 1`,
    [value, value],
  );
}

export function findAuthRowById(db, id) {
  return db.get(
    `SELECT id, email, username, password_hash, hash_params, status, must_change_password,
            failed_login_attempts, locked_until
       FROM users WHERE id = ? AND deleted_at IS NULL`,
    [id],
  );
}

export function listUsers(db, { q = '', status = '', limit = 50, offset = 0 } = {}) {
  const where = ['u.deleted_at IS NULL'];
  const params = [];
  if (q) {
    where.push('(u.email LIKE ? OR u.username LIKE ? OR u.display_name LIKE ?)');
    const like = `%${q}%`;
    params.push(like, like, like);
  }
  if (status && ['pending_password', 'active', 'disabled'].includes(status)) {
    where.push('u.status = ?');
    params.push(status);
  }
  const clause = `WHERE ${where.join(' AND ')}`;
  const total = db.get(`SELECT count(*) AS c FROM users u ${clause}`, params).c;
  const rows = db.all(
    `SELECT ${PUBLIC_SELECT}, ${ROLES_SUBQUERY} FROM users u ${clause}
      ORDER BY u.id ASC LIMIT ? OFFSET ?`,
    [...params, limit, offset],
  );
  return { total, items: rows.map(toPublic) };
}

export function createUser(db, { email, username, displayName = '', passwordHash, hashParams, createdBy = null, mustChangePassword = true, status = 'active' }) {
  const res = db.run(
    `INSERT INTO users (email, username, display_name, password_hash, hash_params, status, must_change_password, created_by, password_changed_at)
     VALUES (?,?,?,?,?,?,?,?,?)`,
    [
      String(email).toLowerCase(),
      username,
      displayName,
      passwordHash,
      JSON.stringify(hashParams ?? {}),
      status,
      mustChangePassword ? 1 : 0,
      createdBy,
      new Date().toISOString(),
    ],
  );
  return findUserById(db, res.lastInsertRowid);
}

export function updatePassword(db, id, { passwordHash, hashParams, clearMustChange = true }) {
  db.run(
    `UPDATE users
        SET password_hash = ?, hash_params = ?, password_changed_at = ?,
            must_change_password = ?, failed_login_attempts = 0, locked_until = NULL,
            status = CASE WHEN status = 'pending_password' THEN 'active' ELSE status END,
            updated_at = ?
      WHERE id = ? AND deleted_at IS NULL`,
    [
      passwordHash,
      JSON.stringify(hashParams ?? {}),
      new Date().toISOString(),
      clearMustChange ? 0 : 1,
      new Date().toISOString(),
      id,
    ],
  );
  return findUserById(db, id);
}

export function setUserStatus(db, id, status) {
  db.run(`UPDATE users SET status = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`, [
    status,
    new Date().toISOString(),
    id,
  ]);
  return findUserById(db, id);
}

export function softDeleteUser(db, id) {
  const res = db.run(`UPDATE users SET status = 'deleted', deleted_at = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`, [
    new Date().toISOString(),
    new Date().toISOString(),
    id,
  ]);
  return res.changes > 0;
}

export function setProfile(db, id, { email, username, displayName }) {
  db.run(`UPDATE users SET email = ?, username = ?, display_name = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`, [
    String(email).toLowerCase(),
    username,
    displayName ?? '',
    new Date().toISOString(),
    id,
  ]);
  return findUserById(db, id);
}

export function recordLoginFailure(db, id, { maxAttempts, lockMs }) {
  const row = db.get(`SELECT failed_login_attempts FROM users WHERE id = ?`, [id]);
  const count = (row?.failed_login_attempts ?? 0) + 1;
  const lockUntil = count >= maxAttempts ? new Date(Date.now() + lockMs).toISOString() : null;
  db.run(`UPDATE users SET failed_login_attempts = ?, locked_until = ?, updated_at = ? WHERE id = ?`, [
    count,
    lockUntil,
    new Date().toISOString(),
    id,
  ]);
  return { count, lockedUntil: lockUntil };
}

export function recordLoginSuccess(db, id) {
  db.run(`UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login_at = ? WHERE id = ?`, [
    new Date().toISOString(),
    id,
  ]);
}

export function emailOrUsernameTaken(db, { email, username, exceptId = null }) {
  const params = [];
  const conds = [];
  if (email) {
    conds.push('lower(email) = lower(?)');
    params.push(email);
  }
  if (username) {
    conds.push('username = ?');
    params.push(username);
  }
  if (!conds.length) return null;
  const row = db.get(`SELECT id, email, username FROM users WHERE (${conds.join(' OR ')}) AND deleted_at IS NULL LIMIT 1`, params);
  if (!row) return null;
  if (exceptId && row.id === exceptId) return null;
  if (email && String(row.email).toLowerCase() === String(email).toLowerCase()) return 'email';
  if (username && row.username === username) return 'username';
  return null;
}

export function countUsers(db, { role } = {}) {
  if (role) {
    return db.get(
      `SELECT count(*) AS c FROM users u JOIN user_roles ur ON ur.user_id = u.id JOIN roles r ON r.id = ur.role_id
        WHERE r.name = ? AND u.deleted_at IS NULL`,
      [role],
    ).c;
  }
  return db.get(`SELECT count(*) AS c FROM users WHERE deleted_at IS NULL`).c;
}

export function countAdmins(db) {
  return db.get(
    `SELECT count(*) AS c FROM users u JOIN user_roles ur ON ur.user_id = u.id JOIN roles r ON r.id = ur.role_id
      WHERE r.name = 'ADMIN' AND u.deleted_at IS NULL AND u.status IN ('active','pending_password')`,
  ).c;
}
