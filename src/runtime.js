/**
 * Composition root.
 *
 * One object holds every service, so `createApp(runtime)` has no hidden global
 * state. Tests build an isolated runtime (own SQLite file or :memory:), and the
 * production server builds one from the environment.
 */
import * as usersRepo from './repositories/users.repo.js';
import { loadConfig } from './config/env.js';
import { createDatabase } from './db/index.js';
import { migrate } from './db/migrate.js';
import { configureLogger, logger } from './utils/logger.js';
import { createAuditService } from './services/audit.service.js';
import { createRbacService } from './services/rbac.service.js';
import { createRateLimitService } from './services/rate-limit.service.js';
import { createAuthService } from './services/auth.service.js';
import { createSettingsService } from './services/settings.service.js';
import { createFileService } from './services/files.service.js';
import { createUrlService } from './services/url.service.js';
import { createAgentService } from './services/agents.service.js';
import { createDashboardService } from './services/dashboard.service.js';
import * as sessionsRepo from './repositories/sessions.repo.js';

export function createRuntime({ config = null, runMigrations = true } = {}) {
  const cfg = config ?? loadConfig();
  configureLogger({ level: cfg.logLevel, json: cfg.jsonLogs });
  const db = createDatabase(cfg);
  if (runMigrations) migrate(db);

  const audit = createAuditService(db);
  const rbac = createRbacService(db);
  const rateLimit = createRateLimitService(db, { max: 120, windowMs: 60_000 });
  const settings = createSettingsService(db);
  const auth = createAuthService({ db, config: cfg, audit, rbac, rateLimit });
  const files = createFileService({ db, config: cfg, audit });
  const urls = createUrlService({ db, config: cfg, audit });
  const agents = createAgentService({ db, audit });
  const dashboard = createDashboardService({ db, audit });

  const runtime = {
    config: cfg,
    db,
    audit,
    rbac,
    rateLimit,
    auth,
    settings,
    files,
    urls,
    agents,
    dashboard,
    users: usersRepo,
    touchSession(id) {
      sessionsRepo.touchSession(db, id);
    },
    purge() {
      return sessionsRepo.purgeExpiredSessions(db);
    },
    close() {
      db.close();
    },
  };
  logger.debug('runtime initialisé', { env: cfg.env, db: cfg.db.path });
  return runtime;
}

export default createRuntime;
