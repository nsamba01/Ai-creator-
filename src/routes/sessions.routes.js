/**
 * Session administration: see who is connected, kick sessions out.
 * Sessions carry no credential material — only anonymised fingerprints.
 */
import { Router } from 'express';
import { wrap, noStore, pagination } from './_helpers.js';
import { forbidden, notFound } from '../utils/errors.js';
import * as sessionsRepo from '../repositories/sessions.repo.js';
import { validateBody, S } from '../middleware/validate.js';

export function createSessionRoutes(runtime) {
  const router = Router();
  const { db, auth, audit, rbac } = runtime;
  const { requireAuth, requirePermission } = runtime.middlewares;

  router.get('/', requireAuth, noStore, wrap(async (req, res) => {
    const { limit, offset } = pagination(req.query, { limit: 50, max: 200 });
    const all = rbac.can(req.user, 'sessions:read:any');
    const rows = sessionsRepo.listActiveSessions(db, { userId: all ? null : req.user.id, limit, offset });
    res.json({
      scope: all ? 'all' : 'own',
      total: db.get(
        all ? `SELECT count(*) AS c FROM sessions WHERE revoked_at IS NULL AND expires_at > ?` : `SELECT count(*) AS c FROM sessions WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?`,
        all ? [new Date().toISOString()] : [req.user.id, new Date().toISOString()],
      ).c,
      items: rows.map((s) => ({ ...s, current: s.id === req.session?.id })),
    });
  }));

  router.delete('/:id', requireAuth, noStore, wrap(async (req, res) => {
    const row = sessionsRepo.findSessionById(db, String(req.params.id).slice(0, 64));
    if (!row) throw notFound('Session introuvable.');
    const own = row.user_id === req.user.id;
    if (!own && !rbac.can(req.user, 'sessions:revoke:any')) throw forbidden('Permission sessions:revoke:any requise.');
    sessionsRepo.revokeSession(db, row.id, own ? 'revoked_by_user' : 'revoked_by_admin');
    audit.record({
      req,
      actor: req.user,
      action: audit.AUDIT.SESSION_REVOKED,
      category: 'security',
      severity: own ? 'notice' : 'warning',
      target_type: 'session',
      target_id: row.id,
      detail: { ownerUserId: row.user_id, own, self: row.id === req.session?.id },
    });
    if (row.id === req.session?.id) {
      auth.logout({ sessionRow: req.session, user: req.user });
      res.setHeader('X-Session-State', 'self_revoked');
    }
    res.json({ ok: true, revoked: row.id, self: row.id === req.session?.id });
  }));

  router.post('/revoke-all', requireAuth, noStore, validateBody({
    userId: S.id({ required: false, label: 'utilisateur' }),
  }), wrap(async (req, res) => {
    const targetId = req.validated.userId ?? req.user.id;
    if (targetId !== req.user.id && !rbac.can(req.user, 'sessions:revoke:any')) throw forbidden('Permission sessions:revoke:any requise.');
    const n = sessionsRepo.revokeAllUserSessions(db, targetId, { reason: targetId === req.user.id ? 'revoked_all_self' : 'revoked_all_admin' });
    sessionsRepo.revokeAllUserRefresh(db, targetId);
    audit.record({
      req,
      actor: req.user,
      action: audit.AUDIT.SESSION_REVOKED,
      category: 'security',
      severity: 'warning',
      target_type: 'user',
      target_id: targetId,
      detail: { count: n },
    });
    const self = targetId === req.user.id;
    if (self) res.setHeader('X-Session-State', 'all_revoked');
    res.json({ ok: true, revoked: n, youAreLoggedOut: self });
  }));

  router.post('/purge', requireAuth, requirePermission('admin:access'), noStore, wrap(async (req, res) => {
    const out = sessionsRepo.purgeExpiredSessions(db);
    audit.record({ req, actor: req.user, action: 'admin.sessions.purged', category: 'admin', detail: out });
    res.json(out);
  }));

  return router;
}

export default createSessionRoutes;
