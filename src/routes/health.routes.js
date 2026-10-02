/**
 * Liveness / readiness / public metadata.
 *
 * These endpoints are intentionally unauthenticated (Docker HEALTHCHECK,
 * orchestrator probes) and therefore expose the minimum: status, version,
 * algorithm family, no paths, no counts, no configuration.
 */
import { Router } from 'express';
import { wrap, noStore } from './_helpers.js';
import { describeAlgorithm } from '../services/password.service.js';

export const VERSION = '1.0.0';

export function createHealthRoutes(runtime) {
  const router = Router();
  const { db, config, auth } = runtime;

  router.get('/healthz', noStore, (req, res) => {
    res.json({
      ok: true,
      status: 'healthy',
      version: VERSION,
      uptimeSeconds: Math.round(process.uptime()),
      environment: config.env,
      passwordHashing: describeAlgorithm(),
    });
  });

  router.get('/readyz', noStore, wrap(async (req, res) => {
    const t0 = Date.now();
    const row = db.get(`SELECT count(*) AS c FROM users`);
    const migrated = db.get(`SELECT count(*) AS c FROM schema_migrations`).c > 0;
    const admins = db.get(`SELECT count(*) AS c FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE r.name = 'ADMIN'`).c;
    const ok = migrated && row !== undefined;
    res.status(ok ? 200 : 503).json({
      ok,
      database: ok ? 'ready' : 'not-ready',
      migrations: migrated,
      adminProvisioned: admins > 0,
      latencyMs: Date.now() - t0,
      sessionTtlMinutes: Math.round(config.session.ttlMs / 60000),
    });
  }));

  /** Non-sensitive capability metadata for the UI. */
  router.get('/meta', noStore, wrap(async (req, res) => {
    res.json({
      name: 'PrinceNsamba AI',
      version: VERSION,
      capabilities: ['auth', 'rbac', 'audit', 'users-admin', 'files', 'documents', 'url-analysis', 'agent-board', 'security-posture'],
      documentTypes: ['.txt', '.md', '.json', '.csv', '.tsv', '.docx', '.xlsx', '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.yml', '.yaml', '.xml'],
      passwordPolicy: { minLength: config.password.minLength, hashing: 'argon2id' },
      csrf: config.csrfEnabled,
      endpoints: ['/api/auth/login', '/api/users', '/api/roles', '/api/sessions', '/api/admin/audit', '/api/files', '/api/documents/analyze', '/api/urls/analyze', '/api/agents/tasks'],
    });
  }));

  return router;
}

export default createHealthRoutes;
