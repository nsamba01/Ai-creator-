/**
 * Migration runner.
 *
 * - applies `src/db/migrations/*.sql` in lexicographic order, exactly once;
 * - records a SHA-256 fingerprint of every applied file and refuses to run on
 *   top of a database whose already-applied migration was edited afterwards
 *   (silent schema drift is a production incident);
 * - each file runs inside a transaction.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { loadConfig } from '../config/env.js';
import { createDatabase } from './index.js';
import { logger } from '../utils/logger.js';

const MIGRATIONS_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'migrations');

export function ensureMigrationsTable(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
    name       TEXT PRIMARY KEY,
    checksum   TEXT NOT NULL,
    applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    duration_ms INTEGER NOT NULL DEFAULT 0
  )`);
}

export function listMigrations(dir = MIGRATIONS_DIR) {
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((f) => /^\d+.*\.sql$/.test(f))
    .sort((a, b) => a.localeCompare(b, 'en', { numeric: true }));
}

export function migrate(db, { dir = MIGRATIONS_DIR } = {}) {
  ensureMigrationsTable(db);
  const applied = new Map(db.all('SELECT name, checksum FROM schema_migrations').map((r) => [r.name, r.checksum]));
  const files = listMigrations(dir);
  const result = { applied: [], skipped: 0, total: files.length };

  for (const name of files) {
    const sql = fs.readFileSync(path.join(dir, name), 'utf8');
    const checksum = crypto.createHash('sha256').update(sql).digest('hex');
    const prev = applied.get(name);
    if (prev) {
      if (prev !== checksum) {
        throw new Error(
          `Intégrité du schéma : la migration appliquée "${name}" a été modifiée après coup (empreinte différente). ` +
            `Ajoutez une nouvelle migration plutôt que d'éditer l'historique.`,
        );
      }
      result.skipped += 1;
      continue;
    }
    const t0 = Date.now();
    db.tx(() => {
      db.exec('PRAGMA defer_foreign_keys = ON');
      db.exec(sql);
      db.run('INSERT INTO schema_migrations (name, checksum, duration_ms) VALUES (?,?,?)', [name, checksum, Date.now() - t0]);
    });
    result.applied.push(name);
    logger.info('migration appliquée', { name });
  }
  return result;
}

/** CLI: `npm run db:migrate` */
export async function runMigrationsCli() {
  const config = loadConfig();
  const db = createDatabase(config);
  try {
    const res = migrate(db);
    process.stdout.write(
      `Migrations : ${res.applied.length} appliquée(s), ${res.skipped} déjà à jour (total ${res.total}).\n` +
        `Base : ${db.path}\n`,
    );
  } finally {
    db.close();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  runMigrationsCli().catch((err) => {
    logger.error('échec de migration', { error: err.message });
    process.exitCode = 1;
  });
}
