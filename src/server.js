/**
 * Process entry point.
 *
 * Responsibilities: load + validate configuration, run migrations, provision
 * the first administrator from the environment (never from source), start
 * listening, keep housekeeping timers, and shut down gracefully on SIGTERM so
 * `docker stop` never truncates a request.
 */
import { loadConfig, ConfigError } from './config/env.js';
import { loadDotenv } from './config/dotenv.js';
import { createRuntime } from './runtime.js';
import { createApp } from './app.js';
import { bootstrapAdmin } from './services/bootstrap.service.js';
import { logger } from './utils/logger.js';
import { describeAlgorithm } from './services/password.service.js';
import { VERSION } from './routes/health.routes.js';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export async function startServer({ configOverride = null, useDotenv = true } = {}) {
  if (useDotenv) {
    // La configuration locale (`.env`) ne remplace jamais l’environnement du
    // processus : en conteneur, les secrets viennent de l’orchestrateur.
    const res = loadDotenv({ root: ROOT });
    if (res.loaded.length) logger.info('configuration locale chargée', { file: path.relative(ROOT, res.file), variables: res.loaded.length });
    if (res.skipped.length) logger.info('variables déjà présentes dans l’environnement', { count: res.skipped.length });
    if (res.warning) logger.warn(res.warning);
  }
  let config;
  try {
    config = configOverride ?? loadConfig();
  } catch (err) {
    if (err instanceof ConfigError) {
      process.stderr.write(`\n[PrinceNsamba AI] Configuration refusée :\n  ${err.message}\n\n`);
      process.exitCode = 78; // EX_CONFIG
      throw err;
    }
    throw err;
  }

  const runtime = createRuntime({ config });
  const bootstrap = await bootstrapAdmin({
    db: runtime.db,
    config,
    audit: runtime.audit,
    rbac: runtime.rbac,
  });

  const app = createApp(runtime);

  const server = await new Promise((resolve, reject) => {
    const s = app.listen(config.port, config.host, () => resolve(s));
    s.once('error', reject);
  });

  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : config.port;

  if (fs.existsSync(path.join(config.root, 'dist', 'index.html'))) {
    logger.info('interface web servie', { path: 'dist/index.html' });
  } else {
    logger.warn('interface web absente — lancez `npm run build` (l’API reste disponible)');
  }

  logger.info('PrinceNsamba AI démarré', {
    version: VERSION,
    environment: config.env,
    host: config.host,
    port,
    database: config.db.path === ':memory:' ? ':memory:' : path.relative(config.root, config.db.path),
    hashing: describeAlgorithm(),
    // Les noms de champs sont choisis pour rester LISIBLES : le rédacteur de
    // journal masque par défaut toute clé évoquant un secret (« cookie »,
    // « csrf », « secret »…), ce qui est voulu pour les données utilisateur
    // mais rendrait inutilisable un journal de démarrage. Ici aucune valeur
    // sensible n'est transportée, seulement des booléens et des politiques.
    browserGuards: { doubleSubmit: config.csrfEnabled, secureFlag: config.cookies.secure, sameSite: config.cookies.sameSite },
    sessionTtlMinutes: Math.round(config.session.ttlMs / 60000),
    keyOrigin: config.secrets.session.source,
    adminBootstrap: bootstrap.created ? 'compte initial créé' : bootstrap.reason,
  });

  if (bootstrap.created && bootstrap.credentialsFile) {
    logger.warn(
      `Mot de passe administrateur temporaire : ${bootstrap.credentialsFile} (permissions 0600). ` +
        `Lisez-le une fois, changez-le à la première connexion, puis supprimez ce fichier.`,
    );
  }

  // Housekeeping: expired sessions/refresh tokens, and rate-limit buckets.
  const housekeeping = setInterval(() => {
    try {
      const purged = runtime.purge();
      runtime.rateLimit.sweep();
      if (purged.sessions || purged.refreshTokens) {
        logger.info('nettoyage des sessions expirées', purged);
      }
    } catch (err) {
      logger.error('échec du nettoyage périodique', { error: err.message });
    }
  }, 15 * 60_000);
  housekeeping.unref();

  let closing = false;
  const shutdown = (signal) => {
    if (closing) return;
    closing = true;
    logger.info('arrêt demandé', { signal });
    clearInterval(housekeeping);
    const force = setTimeout(() => {
      logger.error('arrêt forcé (délai dépassé)');
      process.exit(1);
    }, 10_000);
    force.unref();
    server.close((err) => {
      if (err) logger.warn('erreur lors de la fermeture du serveur', { error: err.message });
      try {
        runtime.close();
      } catch {
        /* already closed */
      }
      clearTimeout(force);
      logger.info('arrêté proprement');
      process.exit(0);
    });
    // Stop accepting keep-alive connections immediately.
    server.closeIdleConnections?.();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('unhandledRejection', (reason) => {
    logger.error('promesse non gérée', { reason: String(reason?.message ?? reason).slice(0, 300) });
  });
  process.on('uncaughtException', (err) => {
    logger.error('exception non interceptée — arrêt', { error: err.message });
    shutdown('uncaughtException');
  });

  return { server, runtime, config, bootstrap, port };
}

const isDirectRun = process.argv[1] && process.argv[1].replace(/\\/g, '/').endsWith('/src/server.js');

if (isDirectRun) {
  startServer().catch((err) => {
    if (!(err instanceof ConfigError)) logger.error('démarrage impossible', { error: err.message });
    process.exit(1);
  });
}

export default startServer;
