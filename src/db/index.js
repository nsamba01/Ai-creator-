/**
 * SQLite access layer (built-in `node:sqlite`, zero native dependency).
 *
 * Provides:
 *  - a single connection with hardened pragmas (WAL, FK enforcement, busy timeout);
 *  - `run/get/all` helpers that normalise parameters. `node:sqlite` refuses
 *    booleans/undefined/Date, so binding is centralised here — that also keeps
 *    every statement fully parameterised (no string interpolation => no SQLi).
 *  - nested-safe transactions.
 */
import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';

const ISO_RE = /^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/;

export function normaliseParam(v) {
  if (v === undefined || v === null) return null;
  if (typeof v === 'boolean') return v ? 1 : 0;
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  if (typeof v === 'bigint') return v;
  if (v instanceof Date) return v.toISOString();
  if (Buffer.isBuffer(v) || v instanceof Uint8Array) return v;
  const s = String(v);
  return s;
}

export function normaliseRow(row) {
  if (!row || typeof row !== 'object') return row;
  const out = {};
  for (const [k, v] of Object.entries(row)) {
    if (typeof v === 'bigint') out[k] = Number(v);
    else out[k] = v;
  }
  return out;
}

/**
 * Arguments of a prepared statement. Positional parameters are passed as an
 * array; named parameters (`WHERE key = :k`) as a plain object, which node:sqlite
 * expects as the *first* argument. Flattening an object with Object.values()
 * used to bind named parameters by index and produced confusing
 * « column index out of range » failures, so the two shapes are kept apart.
 */
function bindArgs(params) {
  if (params === undefined || params === null) return [];
  if (Array.isArray(params)) return params.map(normaliseParam);
  if (typeof params === 'object' && !(params instanceof Uint8Array)) {
    const named = {};
    for (const [k, v] of Object.entries(params)) named[k.replace(/^[:@$]/, '')] = normaliseParam(v);
    return [named];
  }
  return [normaliseParam(params)];
}

export function createDatabase(config) {
  const inMemory = config.db.path === ':memory:';
  if (!inMemory) {
    fs.mkdirSync(path.dirname(config.db.path), { recursive: true, mode: 0o700 });
  }
  const handle = new DatabaseSync(config.db.path, {
    open: true,
    readOnly: false,
    enableForeignKeyConstraints: true,
    enableDoubleQuotedStringLiterals: false,
    allowExtension: false, // SQLite extensions are never loadable
  });

  handle.exec('PRAGMA busy_timeout = ' + Math.max(100, config.db.busyTimeoutMs | 0));
  if (!inMemory) handle.exec('PRAGMA journal_mode = WAL');
  handle.exec('PRAGMA synchronous = NORMAL');
  handle.exec('PRAGMA foreign_keys = ON');
  handle.exec('PRAGMA temp_store = MEMORY');
  handle.exec('PRAGMA secure_delete = ON');

  const db = {
    handle,
    config,
    path: config.db.path,
    exec(sql) {
      handle.exec(sql);
    },
    run(sql, params = []) {
      const stmt = handle.prepare(sql);
      const res = stmt.run(...bindArgs(params));
      return {
        changes: Number(res?.changes ?? 0),
        lastInsertRowid: Number(res?.lastInsertRowid ?? 0),
      };
    },
    get(sql, params = []) {
      const stmt = handle.prepare(sql);
      const row = stmt.get(...bindArgs(params));
      return row === undefined ? undefined : normaliseRow(row);
    },
    all(sql, params = []) {
      const stmt = handle.prepare(sql);
      return stmt.all(...bindArgs(params)).map(normaliseRow);
    },
    pluck(sql, params = []) {
      const row = db.get(sql, params);
      if (!row) return undefined;
      const k = Object.keys(row)[0];
      return row[k];
    },
    exists(sql, params = []) {
      return db.get(sql, params) !== undefined;
    },
    /** Nested-safe transaction. */
    tx(fn) {
      const depth = (db._depth = (db._depth ?? 0) + 1);
      if (depth === 1) handle.exec('BEGIN IMMEDIATE');
      else handle.exec(`SAVEPOINT sp_${depth}`);
      try {
        const result = fn(db);
        if (result && typeof result.then === 'function') {
          throw new Error('db.tx() attend une fonction synchrone');
        }
        if (depth === 1) handle.exec('COMMIT');
        else handle.exec(`RELEASE sp_${depth}`);
        db._depth -= 1;
        return result;
      } catch (err) {
        try {
          if (depth === 1) handle.exec('ROLLBACK');
          else handle.exec(`ROLLBACK TO sp_${depth}`);
        } catch {
          /* keep original error */
        }
        db._depth -= 1;
        throw err;
      }
    },
    nowIso() {
      return new Date().toISOString().replace(/\.\d{0,}Z$/, (m) => (m.length >= 5 ? `${m.slice(0, 5)}Z` : '.000Z'));
    },
    /** ISO timestamp strictly in the past/future (string compare on UTC ISO). */
    isoOffset(ms) {
      const d = new Date(Date.now() + ms);
      const s = d.toISOString();
      return ISO_RE.test(s) ? s : s;
    },
    close() {
      try {
        handle.close();
      } catch {
        /* already closed */
      }
    },
  };

  return db;
}

export default createDatabase;
