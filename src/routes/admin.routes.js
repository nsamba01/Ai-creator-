/**
 * Admin surface: dashboard, settings, audit, agents, security posture,
 * health/meta. Permissions are checked per route; the admin UI is only a
 * view over these APIs.
 */
import { Router } from 'express';
import { wrap, noStore, toCsv, pagination } from './_helpers.js';
import { validateBody, S } from '../middleware/validate.js';
import { badRequest } from '../utils/errors.js';
import { describeAlgorithm } from '../services/password.service.js';
import * as usersRepo from '../repositories/users.repo.js';

export function createAdminRoutes(runtime) {
  const router = Router();
  const { db, config, audit, rbac, settings, dashboard, agents, rateLimit, files } = runtime;
  const { requireAuth, requirePermission } = runtime.middlewares;

  /* ------------------------------- dashboard ------------------------------ */
  router.get('/dashboard', requireAuth, noStore, wrap(async (req, res) => {
    const isAdmin = rbac.can(req.user, 'admin:access');
    if (!isAdmin) {
      res.json({ scope: 'self', self: dashboard.self(req.user.id), agents: agents.list() });
      return;
    }
    res.json({
      scope: 'admin',
      overview: dashboard.overview(),
      agents: agents.list(),
      posture: dashboard.posture(config, audit),
      files: files.stats(),
    });
  }));

  /* ------------------------------- settings ------------------------------- */
  router.get('/settings', requireAuth, requirePermission('settings:read'), noStore, wrap(async (req, res) => {
    res.json({ settings: settings.all({ includePrivate: rbac.can(req.user, 'settings:update') }), effective: settings.effective() });
  }));

  router.put('/settings', requireAuth, requirePermission('settings:update'), noStore, wrap(async (req, res) => {
    const body = req.body ?? {};
    const entries = body.entries && typeof body.entries === 'object' ? body.entries : null;
    const pairs = entries ? Object.entries(entries) : body.key !== undefined ? [[body.key, body.value]] : [];
    if (!pairs.length) throw badRequest('Rien à modifier : { key, value } ou { entries: { clé: valeur } } attendu.');
    if (pairs.length > 20) throw badRequest('Au plus 20 clés par requête.');
    const updated = [];
    const rejected = [];
    db.tx(() => {
      for (const [key, value] of pairs) {
        try {
          const out = settings.set({ key: String(key).slice(0, 64), value, actorId: req.user.id });
          updated.push({ key: out.key, value: out.masked ? '[défini]' : out.value });
        } catch (err) {
          rejected.push({ key: String(key).slice(0, 64), reason: err.message });
        }
      }
    });
    audit.record({
      req,
      actor: req.user,
      action: audit.AUDIT.SETTINGS_UPDATED,
      category: 'admin',
      severity: 'warning',
      detail: { count: updated.length, keys: updated.map((u) => u.key).slice(0, 20), rejected: rejected.length },
    });
    if (updated.some((u) => u.key === 'security.session_ttl_minutes')) rbac.invalidate();
    res.json({ updated, rejected, effective: settings.effective() });
  }));

  /* --------------------------------- audit -------------------------------- */
  router.get('/audit', requireAuth, requirePermission('audit:read'), noStore, wrap(async (req, res) => {
    const { limit, offset } = pagination(req.query, { limit: 50, max: 500 });
    const out = audit.query({
      limit,
      offset,
      action: String(req.query.action ?? '').slice(0, 64),
      category: String(req.query.category ?? '').slice(0, 24),
      severity: String(req.query.severity ?? '').slice(0, 12),
      outcome: String(req.query.outcome ?? '').slice(0, 12),
      q: String(req.query.q ?? '').slice(0, 120),
      actorId: req.query.actorId ? Number(req.query.actorId) : null,
      from: String(req.query.from ?? '').slice(0, 40),
      to: String(req.query.to ?? '').slice(0, 40),
    });
    res.json({ ...out, stats: audit.stats(24) });
  }));

  router.get('/audit/export', requireAuth, requirePermission('audit:export'), wrap(async (req, res) => {
    const out = audit.query({ limit: 5000, offset: 0, severity: String(req.query.severity ?? '').slice(0, 12), category: String(req.query.category ?? '').slice(0, 24) });
    const csv = toCsv(
      out.items.map((r) => ({ ...r, detail: r.detail ? JSON.stringify(r.detail) : '' })),
      [
        { key: 'occurredAt', label: 'Horodatage' },
        { key: 'actorLabel', label: 'Acteur' },
        { key: 'action', label: 'Action' },
        { key: 'category', label: 'Catégorie' },
        { key: 'targetType', label: 'Cible (type)' },
        { key: 'targetId', label: 'Cible (id)' },
        { key: 'outcome', label: 'Résultat' },
        { key: 'severity', label: 'Sévérité' },
        { key: 'ipHash', label: 'EMPREINTE_IP' },
        { key: 'detail', label: 'Detail' },
      ],
    );
    audit.record({ req, actor: req.user, action: 'admin.audit.exported', category: 'admin', severity: 'warning', detail: { rows: out.items.length } });
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="audit-${new Date().toISOString().slice(0, 10)}.csv"`);
    res.setHeader('Cache-Control', 'no-store');
    res.send(`\uFEFF${csv}`);
  }));

  /* ----------------------------- security posture ------------------------- */
  router.get('/security', requireAuth, wrap(async (req, res) => {
    const canRead = rbac.can(req.user, 'security:read') || rbac.can(req.user, 'admin:access');
    const posture = dashboard.posture(config, audit);
    if (!canRead) {
      // A standard user may see only what concerns their own safety.
      res.json({
        scope: 'self',
        checks: posture.checks.filter((c) => ['hashing', 'cookies', 'csrf'].includes(c.id)),
        mySessions: db.get(`SELECT count(*) AS c FROM sessions WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?`, [req.user.id, new Date().toISOString()]).c,
      });
      return;
    }
    res.json({
      scope: 'admin',
      ...posture,
      buckets: rateLimit.blockedBuckets(10).map((b) => ({ ...b, bucketKey: undefined, keyFingerprint: `${String(b.bucket_key).slice(0, 8)}…` })),
      loginAttempts: db.all(`SELECT bucket_key, count, last_at, locked_until FROM login_attempts ORDER BY last_at DESC LIMIT 10`)
        .map((r) => ({ keyFingerprint: `${String(r.bucket_key).slice(0, 10)}…`, count: r.count, lastAt: r.last_at, lockedUntil: r.locked_until })),
      hashing: describeAlgorithm(),
      config: {
        csrfEnabled: config.csrfEnabled,
        cookieSecure: config.cookies.secure,
        sameSite: config.cookies.sameSite,
        sessionTtlMinutes: Math.round(config.session.ttlMs / 60000),
        passwordMinLength: config.password.minLength,
        argon2: config.password.argon2,
        lockout: config.lockout,
        urlPolicy: { allowPrivate: config.url.allowPrivate, maxBytes: config.url.maxBytes, timeoutMs: config.url.timeoutMs, ports: [...config.url.allowedPorts] },
        uploadPolicy: { maxBytes: config.uploads.maxBytes, enforceMagic: config.uploads.enforceMagic },
        corsOrigins: [...config.cors.allowedOrigins],
      },
      warnings: buildWarnings(config, posture, rbac),
    });
  }));

  /* --------------------------------- users -------------------------------- */
  router.get('/security/users-at-risk', requireAuth, requirePermission('audit:read'), noStore, wrap(async (req, res) => {
    const locked = db.all(`SELECT id, email, username, locked_until, failed_login_attempts FROM users WHERE locked_until IS NOT NULL AND locked_until > ? AND deleted_at IS NULL`, [new Date().toISOString()]);
    const stale = db.all(`SELECT id, email, username, last_login_at FROM users WHERE deleted_at IS NULL AND status = 'active' AND (last_login_at IS NULL OR last_login_at < ?) ORDER BY last_login_at LIMIT 25`, [
      new Date(Date.now() - 90 * 86_400_000).toISOString(),
    ]);
    // Les comptes créés par l’administrateur restent « active » avec
    // must_change_password = 1 : filtrer sur l’ancien statut les masquait.
    const mustChange = db.all(
      `SELECT id, email, username, status, created_at AS createdAt, last_login_at AS lastLoginAt
         FROM users
        WHERE deleted_at IS NULL AND must_change_password = 1
        ORDER BY created_at
        LIMIT 25`,
    );
    res.json({ locked, inactive: stale, mustChangePassword: mustChange });
  }));

  return router;
}

function buildWarnings(config, posture, rbac) {
  const w = [];
  if (!config.isProd) w.push({ level: 'notice', message: 'NODE_ENV != production : les contrôles stricts (HSTS, cookies Secure, secrets obligatoires) sont assouplis.' });
  if (config.secrets.session.source !== 'env') w.push({ level: 'warning', message: `SESSION_SECRET provient de « ${config.secrets.session.source} ». En production, injectez un secret explicite (openssl rand -hex 32).` });
  if (!config.cookies.secure) w.push({ level: 'warning', message: 'Cookies sans attribut Secure : réservez cette configuration au développement local.' });
  if (posture.counts.admins === 1) w.push({ level: 'notice', message: 'Un seul administrateur : pensez à un compte de secours.' });
  if (config.trustProxy) w.push({ level: 'notice', message: 'SECURE_PROXY=1 : la résolution d’IP client repose sur X-Forwarded-For, à ne Activer que derrière un reverse-proxy de confiance.' });
  if (posture.checks.some((c) => !c.ok)) w.push({ level: 'critical', message: 'Des contrôles de sécurité sont insatisfaits : voir la liste des vérifications.' });
  return w;
}

