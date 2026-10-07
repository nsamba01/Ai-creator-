/**
 * Sessions + refresh-token repository.
 *
 * Threat model notes:
 *  - the browser holds a random token; the DB holds HMAC(token) only;
 *  - session id is rotated on login and on privilege change (fixation);
 *  - refresh tokens are grouped in "families"; replaying an already-rotated
 *    token revokes the whole family (stolen-token detection);
 *  - expiry is enforced on the server, never by the client clock.
 */
import { randomHex } from '../utils/crypto.js';

/**
 * Persists a session.
 * The caller supplies the already-HMACed token (`tokenHash`): the raw token is
 * only ever returned here, so it cannot be persisted by accident.
 */
export function createSession(db, { userId, tokenHash, ttlMs, ipHash = null, userAgentHash = null, csrfToken = randomHex(16) }) {
  const id = randomHex(12);
  const now = Date.now();
  const expiresAt = new Date(now + ttlMs).toISOString();
  db.run(
    `INSERT INTO sessions (id, user_id, token_hash, csrf_token, ip_hash, user_agent_hash, created_at, last_seen_at, expires_at)
     VALUES (?,?,?,?,?,?,?,?,?)`,
    [id, userId, tokenHash, csrfToken, ipHash, userAgentHash, new Date(now).toISOString(), new Date(now).toISOString(), expiresAt],
  );
  return { id, csrfToken, expiresAt };
}

export function findSessionByTokenHash(db, tokenHash) {
  if (!tokenHash) return undefined;
  return db.get(
    `SELECT s.id, s.user_id, s.csrf_token, s.created_at, s.last_seen_at, s.expires_at, s.revoked_at, s.ip_hash, s.user_agent_hash,
            u.email, u.username, u.status, u.must_change_password
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?`,
    [tokenHash],
  );
}

export function findSessionById(db, id) {
  return db.get(
    `SELECT s.*, u.email, u.username, u.status FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?`,
    [id],
  );
}

export function touchSession(db, id, { updateCsrf = null } = {}) {
  if (updateCsrf) {
    db.run(`UPDATE sessions SET last_seen_at = ?, csrf_token = ? WHERE id = ?`, [new Date().toISOString(), updateCsrf, id]);
  } else {
    db.run(`UPDATE sessions SET last_seen_at = ? WHERE id = ?`, [new Date().toISOString(), id]);
  }
}

export function setSessionCsrf(db, id, csrfToken) {
  db.run(`UPDATE sessions SET csrf_token = ? WHERE id = ?`, [csrfToken, id]);
}

export function revokeSession(db, id, reason = 'logout') {
  const res = db.run(`UPDATE sessions SET revoked_at = ?, revoke_reason = ? WHERE id = ? AND revoked_at IS NULL`, [
    new Date().toISOString(),
    String(reason).slice(0, 64),
    id,
  ]);
  return res.changes > 0;
}

export function revokeAllUserSessions(db, userId, { exceptId = null, reason = 'revoked' } = {}) {
  const res = exceptId
    ? db.run(
        `UPDATE sessions SET revoked_at = ?, revoke_reason = ?
          WHERE user_id = ? AND revoked_at IS NULL AND id <> ?`,
        [new Date().toISOString(), String(reason).slice(0, 64), userId, exceptId],
      )
    : db.run(`UPDATE sessions SET revoked_at = ?, revoke_reason = ? WHERE user_id = ? AND revoked_at IS NULL`, [
        new Date().toISOString(),
        String(reason).slice(0, 64),
        userId,
      ]);
  return res.changes;
}

export function listActiveSessions(db, { userId = null, limit = 100, offset = 0 } = {}) {
  const now = new Date().toISOString();
  const base = `s.revoked_at IS NULL AND s.expires_at > ?`;
  const params = [now];
  if (userId) {
    params.push(userId);
    return db.all(
      `SELECT s.id, s.user_id, s.created_at, s.last_seen_at, s.expires_at, s.ip_hash, s.user_agent_hash,
              u.email, u.username, u.display_name
         FROM sessions s JOIN users u ON u.id = s.user_id
        WHERE ${base} AND s.user_id = ?
        ORDER BY s.last_seen_at DESC LIMIT ? OFFSET ?`,
      [...params, limit, offset],
    ).map(safeSessionDto);
  }
  return db.all(
    `SELECT s.id, s.user_id, s.created_at, s.last_seen_at, s.expires_at, s.ip_hash, s.user_agent_hash,
            u.email, u.username, u.display_name
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE ${base}
      ORDER BY s.last_seen_at DESC LIMIT ? OFFSET ?`,
    [now, limit, offset],
  ).map(safeSessionDto);
}

/** Never leaks token_hash / csrf_token. */
export function safeSessionDto(row) {
  return {
    id: row.id,
    userId: row.user_id,
    email: row.email,
    username: row.username,
    displayName: row.display_name ?? row.username,
    createdAt: row.created_at,
    lastSeenAt: row.last_seen_at,
    expiresAt: row.expires_at,
    ipHash: row.ip_hash,
    userAgentHash: row.user_agent_hash,
    current: row.current === true,
  };
}

export function purgeExpiredSessions(db, { graceMs = 86_400_000 } = {}) {
  const cutoff = new Date(Date.now() - graceMs).toISOString();
  const s = db.run(`DELETE FROM sessions WHERE expires_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?)`, [cutoff, cutoff]);
  const r = db.run(`DELETE FROM refresh_tokens WHERE expires_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?)`, [cutoff, cutoff]);
  return { sessions: s.changes, refreshTokens: r.changes };
}

/* ------------------------------- refresh tokens ------------------------- */

export function issueRefreshToken(db, { userId, familyId = randomHex(12), tokenHash = randomHex(32), sessionId = null, ttlMs }) {
  const expiresAt = new Date(Date.now() + ttlMs).toISOString();
  db.run(
    `INSERT INTO refresh_tokens (user_id, family_id, token_hash, issued_for_session, created_at, expires_at)
     VALUES (?,?,?,?,?,?)`,
    [userId, familyId, tokenHash, sessionId, new Date().toISOString(), expiresAt],
  );
  return { tokenHash, familyId, expiresAt };
}

export function findRefreshByHash(db, tokenHash) {
  if (!tokenHash) return undefined;
  return db.get(
    `SELECT rt.*, u.email, u.username, u.status FROM refresh_tokens rt JOIN users u ON u.id = rt.user_id WHERE rt.token_hash = ?`,
    [tokenHash],
  );
}

export function markRefreshUsed(db, id, replacedBy) {
  db.run(`UPDATE refresh_tokens SET used_at = ?, replaced_by = ? WHERE id = ?`, [new Date().toISOString(), replacedBy ?? null, id]);
}

export function revokeRefreshFamily(db, familyId, reason = 'rotated') {
  const res = db.run(
    `UPDATE refresh_tokens SET revoked_at = ?, used_at = COALESCE(used_at, ?) WHERE family_id = ? AND revoked_at IS NULL`,
    [new Date().toISOString(), new Date().toISOString(), familyId],
  );
  return res.changes;
}

export function revokeAllUserRefresh(db, userId, reason = 'sessions_revoked') {
  const res = db.run(`UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`, [
    new Date().toISOString(),
    userId,
  ]);
  return res.changes;
}

export default {
  createSession,
  findSessionByTokenHash,
  revokeSession,
  revokeAllUserSessions,
  listActiveSessions,
  purgeExpiredSessions,
  issueRefreshToken,
  findRefreshByHash,
  markRefreshUsed,
  revokeRefreshFamily,
};
