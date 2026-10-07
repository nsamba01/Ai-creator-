/**
 * Audit log service (append-only).
 *
 * Records authentication and administrative events. Passwords, hashes,
 * tokens, cookies and secrets are structurally impossible to persist here:
 * payloads pass through `redact()` and forbidden keys are dropped twice
 * (once by pattern, once by explicit list).
 */
import { redact, REDACTED } from '../utils/logger.js';
import { logger } from '../utils/logger.js';

const FORBIDDEN_KEYS = new Set([
  'password',
  'currentpassword',
  'newpassword',
  'passwordhash',
  'passwordconfirm',
  'temppassword',
  'token',
  'refreshtoken',
  'sessiontoken',
  'csrftoken',
  'secret',
  'authorization',
  'cookie',
  'setcookie',
]);

export const AUDIT = {
  LOGIN_SUCCESS: 'auth.login.success',
  LOGIN_FAILURE: 'auth.login.failure',
  LOGIN_BLOCKED: 'auth.login.blocked',
  LOGOUT: 'auth.logout',
  LOCKOUT: 'auth.account.locked',
  PASSWORD_CHANGED: 'auth.password.changed',
  PASSWORD_RESET_ISSUED: 'auth.password.reset_issued',
  PASSWORD_RESET_CONSUMED: 'auth.password.reset_consumed',
  SESSION_REVOKED: 'auth.session.revoked',
  REFRESH_REUSE_DETECTED: 'auth.refresh.reuse_detected',
  CSRF_FAILURE: 'security.csrf.failure',
  AUTHZ_DENIED: 'security.authorization.denied',
  USER_CREATED: 'admin.user.created',
  USER_UPDATED: 'admin.user.updated',
  USER_DISABLED: 'admin.user.disabled',
  USER_ENABLED: 'admin.user.enabled',
  USER_DELETED: 'admin.user.deleted',
  USER_PASSWORD_RESET: 'admin.user.password_reset',
  ROLE_CREATED: 'admin.role.created',
  ROLE_UPDATED: 'admin.role.permissions_updated',
  ROLE_DELETED: 'admin.role.deleted',
  SETTINGS_UPDATED: 'admin.settings.updated',
  FILE_UPLOADED: 'file.uploaded',
  FILE_DOWNLOADED: 'file.downloaded',
  FILE_DELETED: 'file.deleted',
  FILE_REJECTED: 'file.rejected',
  DOCUMENT_ANALYZED: 'document.analyzed',
  VIDEO_REGISTERED: 'video.registered',
  VIDEO_PROBED: 'video.probed',
  VIDEO_QUARANTINED: 'video.quarantined',
  VIDEO_RELEASED: 'video.released',
  URL_ANALYZED: 'url.analyzed',
  URL_BLOCKED: 'url.blocked',
  AGENT_TASK_UPDATED: 'agent.task.updated',
  AGENT_TASK_CREATED: 'agent.task.created',
};

export function createAuditService(db) {
  /**
   * @param {object} entry
   * @param {object} [entry.req] express request (for ip/ua/request id)
   * @param {object} [entry.actor] authenticated user
   */
  function record(entry) {
    const {
      req,
      actor = null,
      action,
      category = 'auth',
      targetType = null,
      targetId = null,
      outcome = 'success',
      severity = 'info',
      detail = null,
      ipHash = null,
      userAgentHash = null,
    } = entry;

    let detailJson = null;
    if (detail && typeof detail === 'object') {
      const scrubbed = dropForbidden(redact(detail));
      if (Object.keys(scrubbed).length) detailJson = JSON.stringify(scrubbed).slice(0, 4000);
    } else if (typeof detail === 'string') {
      detailJson = JSON.stringify({ note: String(redact(detail)).slice(0, 500) });
    }

    try {
      db.run(
        `INSERT INTO audit_logs
           (actor_id, actor_label, action, category, target_type, target_id, outcome, severity, ip_hash, user_agent_hash, request_id, detail_json)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
        [
          actor?.id ?? null,
          actor?.email ?? actor?.username ?? 'anonymous',
          String(action).slice(0, 64),
          String(category).slice(0, 24),
          targetType ? String(targetType).slice(0, 32) : null,
          targetId === null || targetId === undefined ? null : String(targetId).slice(0, 64),
          ['success', 'failure', 'blocked', 'error'].includes(outcome) ? outcome : 'error',
          ['debug', 'info', 'notice', 'warning', 'critical'].includes(severity) ? severity : 'info',
          ipHash ?? req?.ipHash ?? null,
          userAgentHash ?? req?.uaHash ?? null,
          req?.id ?? null,
          detailJson,
        ],
      );
    } catch (err) {
      // Audit failure must never open a request, but must be loud in logs.
      logger.error('échec d’écriture du journal d’audit', { action, error: err.message });
    }
  }

  function dropForbidden(obj) {
    const out = {};
    for (const [k, v] of Object.entries(obj ?? {})) {
      if (FORBIDDEN_KEYS.has(k.toLowerCase())) continue;
      if (v === REDACTED) {
        out[k] = REDACTED;
        continue;
      }
      out[k] = v && typeof v === 'object' ? dropForbidden(v) : v;
    }
    return out;
  }

  function query({ limit = 50, offset = 0, action = '', actorId = null, severity = '', category = '', outcome = '', q = '', from = '', to = '' } = {}) {
    const where = [];
    const params = [];
    if (action) {
      where.push('a.action = ?');
      params.push(action);
    }
    if (category) {
      where.push('a.category = ?');
      params.push(category);
    }
    if (severity) {
      where.push('a.severity = ?');
      params.push(severity);
    }
    if (outcome) {
      where.push('a.outcome = ?');
      params.push(outcome);
    }
    if (actorId) {
      where.push('a.actor_id = ?');
      params.push(Number(actorId));
    }
    if (from) {
      where.push('a.occurred_at >= ?');
      params.push(String(from));
    }
    if (to) {
      where.push('a.occurred_at <= ?');
      params.push(String(to));
    }
    if (q) {
      where.push('(a.actor_label LIKE ? OR a.action LIKE ? OR a.detail_json LIKE ?)');
      const like = `%${q}%`;
      params.push(like, like, like);
    }
    const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const total = db.get(`SELECT count(*) AS c FROM audit_logs a ${clause}`, params).c;
    const rows = db.all(
      `SELECT a.* FROM audit_logs a ${clause} ORDER BY a.id DESC LIMIT ? OFFSET ?`,
      [...params, Math.min(500, Math.max(1, limit)), Math.max(0, offset)],
    );
    return {
      total,
      items: rows.map((r) => ({
        id: r.id,
        occurredAt: r.occurred_at,
        actorId: r.actor_id,
        actorLabel: r.actor_label,
        action: r.action,
        category: r.category,
        targetType: r.target_type,
        targetId: r.target_id,
        outcome: r.outcome,
        severity: r.severity,
        ipHash: r.ip_hash,
        userAgentHash: r.user_agent_hash,
        requestId: r.request_id,
        detail: safeParse(r.detail_json),
      })),
    };
  }

  function stats(hours = 24) {
    const since = new Date(Date.now() - hours * 3600_000).toISOString();
    const byAction = db.all(
      `SELECT action, outcome, count(*) AS c FROM audit_logs WHERE occurred_at >= ? GROUP BY action, outcome ORDER BY c DESC LIMIT 25`,
      [since],
    );
    return {
      window: `${hours}h`,
      total: db.get(`SELECT count(*) AS c FROM audit_logs WHERE occurred_at >= ?`, [since]).c,
      failures: db.get(`SELECT count(*) AS c FROM audit_logs WHERE occurred_at >= ? AND outcome IN ('failure','blocked')`, [since]).c,
      critical: db.get(`SELECT count(*) AS c FROM audit_logs WHERE occurred_at >= ? AND severity = 'critical'`, [since]).c,
      byAction,
      lastEventAt: db.get(`SELECT max(occurred_at) AS m FROM audit_logs`)?.m ?? null,
    };
  }

  return { record, query, stats, AUDIT };
}

function safeParse(s) {
  if (!s) return null;
  try {
    return JSON.parse(s);
  } catch {
    return { note: String(s).slice(0, 200) };
  }
}

export default createAuditService;
