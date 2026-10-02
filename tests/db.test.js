/**
 * SQLite layer: migrations and their integrity, schema constraints, indexes,
 * soft delete, transactions, parameter normalisation.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { createDatabase, normaliseParam, normaliseRow } from '../src/db/index.js';
import { migrate, ensureMigrationsTable, listMigrations } from '../src/db/migrate.js';
import { loadConfig } from '../src/config/env.js';
import { boot } from './helpers.js';

const MIGRATIONS_DIR = new URL('../src/db/migrations/', import.meta.url).pathname;

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'ps-db-'));
}

function freshDb() {
  const dir = tempDir();
  const config = loadConfig({ NODE_ENV: 'test', DATA_DIR: dir, LOG_LEVEL: 'silent', LOG_JSON: '0', SESSION_SECRET: 'x'.repeat(48), STATE_SECRET: 'y'.repeat(48) }, { DB_PATH: path.join(dir, 't.db'), PORT: '0' });
  const db = createDatabase(config);
  return { db, dir, config };
}

describe('migrations', () => {
  let ctx;
  before(async () => {
    ctx = await boot();
  });
  after(async () => {
    await ctx.close();
  });

  it('sont ordonnées, nommées et appliquées une seule fois', async () => {
    const files = listMigrations(MIGRATIONS_DIR);
    assert.ok(files.length >= 2, 'au moins deux migrations');
    assert.deepEqual(files, [...files].sort((a, b) => a.localeCompare(b, 'en', { numeric: true })), 'triées par préfixe numérique');
    for (const f of files) assert.match(f, /^\d{3}_.+\.sql$/, `nommage strict : ${f}`);
    const rows = ctx.runtime.db.all(`SELECT name, checksum, duration_ms FROM schema_migrations ORDER BY name`);
    assert.equal(rows.length, files.length, 'toutes appliquées');
    for (const r of rows) {
      assert.match(r.checksum, /^[0-9a-f]{64}$/, 'empreinte SHA-256 enregistrée');
      assert.ok(r.duration_ms >= 0);
    }
    const again = migrate(ctx.runtime.db, { dir: MIGRATIONS_DIR });
    assert.deepEqual(again.applied, [], 'aucune réapplication');
    assert.equal(again.skipped, files.length, 'toutes reconnues comme déjà appliquées');
  });

  it('refusent une modification de migration déjà appliquée', () => {
    const { db, dir } = freshDb();
    try {
      const first = migrate(db, { dir: MIGRATIONS_DIR });
      assert.ok(first.applied.length >= 2, 'première application complète');
      const copy = tempDir();
      for (const f of listMigrations(MIGRATIONS_DIR)) fs.copyFileSync(path.join(MIGRATIONS_DIR, f), path.join(copy, f));
      const target = path.join(copy, listMigrations(copy)[0]);
      fs.appendFileSync(target, '\n-- modification a posteriori\n');
      assert.throws(
        () => migrate(db, { dir: copy }),
        /Intégrité du schéma|empreinte différente/,
        'l’édition de l’historique est détectée',
      );
      fs.rmSync(copy, { recursive: true, force: true });
    } finally {
      db.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('appliquent une nouvelle migration sans toucher aux précédentes', () => {
    const { db, dir } = freshDb();
    try {
      const copy = tempDir();
      for (const f of listMigrations(MIGRATIONS_DIR)) fs.copyFileSync(path.join(MIGRATIONS_DIR, f), path.join(copy, f));
      fs.writeFileSync(path.join(copy, '900_test.sql'), 'CREATE TABLE IF NOT EXISTS zzz_probe (id INTEGER PRIMARY KEY, note TEXT);\n');
      const out = migrate(db, { dir: copy });
      assert.ok(out.applied.includes('900_test.sql'), 'la nouvelle migration passe');
      assert.ok(ctx.runtime.db.get(`SELECT count(*) AS c FROM sqlite_master WHERE type='table' AND name='zzz_probe'`).c === 0, 'et ne contamine pas la base de l’application');
      const again = migrate(db, { dir: copy });
      assert.deepEqual(again.applied, [], 'idempotente');
      fs.rmSync(copy, { recursive: true, force: true });
    } finally {
      db.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('roulent en transaction : une migration invalide ne laisse pas de demi-schéma', () => {
    const { db, dir } = freshDb();
    try {
      ensureMigrationsTable(db);
      const copy = tempDir();
      fs.writeFileSync(path.join(copy, '999_broken.sql'), 'CREATE TABLE ok_before (id INTEGER);CREATE TABLE ok_before (id INTEGER);\n');
      assert.throws(() => migrate(db, { dir: copy }), /Error|existe déjà|already exists/i);
      const created = db.get(`SELECT count(*) AS c FROM sqlite_master WHERE type='table' AND name='ok_before'`).c;
      assert.equal(created, 0, 'aucune table partielle');
      const recorded = db.get(`SELECT count(*) AS c FROM schema_migrations WHERE name='999_broken.sql'`).c;
      assert.equal(recorded, 0, 'et aucune trace dans l’historique');
      fs.rmSync(copy, { recursive: true, force: true });
    } finally {
      db.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('schéma et intégrité', () => {
  let ctx;
  before(async () => {
    ctx = await boot();
  });
  after(async () => {
    await ctx.close();
  });

  it('déclare les tables attendues avec clés, contraintes et index', () => {
    const tables = ctx.runtime.db.all(`SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`).map((r) => r.name);
    for (const t of [
      'users',
      'roles',
      'permissions',
      'user_roles',
      'role_permissions',
      'sessions',
      'refresh_tokens',
      'password_reset_tokens',
      'audit_logs',
      'settings',
      'files',
      'document_analyses',
      'url_analyses',
      'agent_tasks',
      'login_attempts',
      'schema_migrations',
    ]) {
      assert.ok(tables.includes(t), `table ${t} présente`);
    }
    const indexes = ctx.runtime.db.all(`SELECT name FROM sqlite_master WHERE type='index' AND sql IS NOT NULL`).map((r) => r.name);
    assert.ok(indexes.length >= 10, `index déclarés (${indexes.length})`);
    for (const t of ['users', 'sessions', 'audit_logs', 'files', 'role_permissions']) {
      assert.ok(indexes.some((i) => i.includes(t.slice(0, 6))) || ctx.runtime.db.all(`PRAGMA index_list(${t})`).length > 0, `${t} est indexée`);
    }
    const fk = ctx.runtime.db.get(`PRAGMA foreign_keys`).foreign_keys;
    assert.equal(Number(fk), 1, 'clés étrangères activées à la connexion');
  });

  it('interdit les doublons métier et les valeurs incohérentes', () => {
    const db = ctx.runtime.db;
    const { hash, params } = { hash: '$argon2id$v=19$m=8192,t=1,p=1$c2FsdA==$ZGlnZXN0ZGlnZXN0ZGlnZXN0ZGlnMDI=', params: { memoryCost: 8192, timeCost: 1, parallelism: 1 } };
    db.run(`INSERT INTO users (email, username, password_hash, hash_params, status) VALUES (?,?,?,?,?)`, ['dup@test.local', 'duplicata', hash, JSON.stringify(params), 'active']);
    assert.throws(() => db.run(`INSERT INTO users (email, username, password_hash, hash_params) VALUES (?,?,?,?)`, ['dup@test.local', 'autre', hash, '{}']), /UNIQUE/, 'e-mail unique');
    assert.throws(() => db.run(`INSERT INTO users (email, username, password_hash, hash_params) VALUES (?,?,?,?)`, ['nouveau@test.local', 'duplicata', hash, '{}']), /UNIQUE/, 'identifiant unique');
    assert.throws(() => db.run(`INSERT INTO users (email, username, password_hash, hash_params, status) VALUES (?,?,?,?,?)`, ['x@test.local', 'x', hash, '{}', 'fantôme']), /CHECK/, 'statut contraint');
    assert.throws(() => db.run(`INSERT INTO audit_logs (action, category, severity, outcome) VALUES ('a','auth','normale','success')`), /CHECK/, 'sévérité contrainte');
    assert.throws(() => db.run(`INSERT INTO users (email, username, status) VALUES (?,?,?)`, ['y@test.local', 'y', 'active']), /NOT NULL/, 'le mot de passe n’est pas optionnel');
  });

  it('ne conserve aucune colonne de mot de passe en clair', () => {
    for (const r of ctx.runtime.db.all(`PRAGMA table_info(users)`)) {
      assert.ok(!/plain|clear|password_plain|motdepasse/i.test(r.name), `colonne ${r.name} acceptable`);
    }
    const cols = ctx.runtime.db.all(`PRAGMA table_info(users)`).map((c) => c.name);
    assert.ok(cols.includes('password_hash'), 'hash stocké');
    assert.ok(cols.includes('hash_params'), 'paramètres de hachage stockés (rehachage)');
    assert.ok(cols.includes('must_change_password'), 'changement forcé à la première connexion');
    assert.ok(cols.includes('deleted_at'), 'suppression logique');
    assert.ok(cols.includes('created_at') && cols.includes('updated_at'), 'horodatages');
  });

  it('rafraîchit updated_at même quand l’écriture l’oublie (migration 003)', () => {
    const before0 = ctx.runtime.db.get(`SELECT updated_at FROM users WHERE id=?`, [ctx.users.admin.id]).updated_at;
    ctx.runtime.db.run(`UPDATE users SET display_name = display_name || '!' WHERE id=?`, [ctx.users.admin.id]);
    const after0 = ctx.runtime.db.get(`SELECT updated_at FROM users WHERE id=?`, [ctx.users.admin.id]).updated_at;
    assert.notEqual(after0, before0, 'le déclencheur d’horodatage joue');
  });

  it('cascade les sessions supprimées, mais refuse d’effacer un compte audité', () => {
    const db = ctx.runtime.db;
    const seed = { hash: '$argon2id$v=19$m=8192,t=1,p=1$c2FsdA==$ZGlnZXN0ZGlnZXN0ZGlnMDI=', params: { memoryCost: 8192, timeCost: 1, parallelism: 1 } };

    // 1. Aucun antécédent d’audit : la suppression physique est possible et les
    //    dépendances suivent (ON DELETE CASCADE).
    db.run(`INSERT INTO users (email, username, password_hash, hash_params, status) VALUES (?,?,?,?,?)`, ['cascade@test.local', 'cascade', seed.hash, JSON.stringify(seed.params), 'active']);
    const uid = db.get(`SELECT id FROM users WHERE email='cascade@test.local'`).id;
    db.run(`INSERT INTO sessions (id, user_id, token_hash, csrf_token, expires_at) VALUES (?,?,?,?,?)`, ['sess-cascade', uid, 'h'.repeat(64), 'c'.repeat(32), '2999-01-01T00:00:00Z']);
    db.run(`INSERT INTO refresh_tokens (user_id, family_id, token_hash, expires_at) VALUES (?,?,?,?)`, [uid, 'fam-1', 'i'.repeat(64), '2999-01-01T00:00:00Z']);
    assert.ok(db.get(`SELECT id FROM sessions WHERE id='sess-cascade'`), 'session créée');
    db.run(`DELETE FROM users WHERE id=?`, [uid]);
    assert.equal(db.get(`SELECT id FROM sessions WHERE id='sess-cascade'`), undefined, 'sessions supprimées en cascade');
    assert.equal(db.get(`SELECT count(*) AS c FROM refresh_tokens WHERE user_id=?`, [uid]).c, 0, 'jetons de rafraîchissement supprimés aussi');

    // 2. Un compte ayant un historique d’audit ne peut PAS être effacé : la
    //    mise à NULL implicite de `audit_logs.actor_id` est bloquée par le
    //    déclencheur d’immuabilité. C’est ce qui impose la suppression logique.
    const adminId = ctx.users.admin.id;
    db.run(`INSERT INTO audit_logs (action, category, actor_id) VALUES ('test.history','system',?)`, [adminId]);
    assert.ok(db.get(`SELECT count(*) AS c FROM audit_logs WHERE actor_id=?`, [adminId]).c >= 1, 'l’administrateur a un historique');
    assert.throws(() => db.run(`DELETE FROM users WHERE id=?`, [adminId]), /append-only|modification interdite/i, 'effacement physique refusé');
    assert.ok(db.get(`SELECT id FROM users WHERE id=?`, [adminId]), 'le compte est intact');
  });

  it('refuse un lien vers une permission ou un rôle inexistant', () => {
    const db = ctx.runtime.db;
    assert.throws(() => db.run(`INSERT INTO user_roles (user_id, role_id) VALUES (?, 987654)`, [ctx.users.admin.id]), /FOREIGN KEY|constraint/i);
    assert.throws(() => db.run(`INSERT INTO role_permissions (role_id, permission_id) VALUES (1, 987654)`), /FOREIGN KEY|constraint/i);
  });

  it('garantit l’unicité des rôles, permissions et paires', () => {
    const db = ctx.runtime.db;
    db.run(`INSERT INTO roles (name, description) VALUES ('QA-temp','rôle de test')`);
    assert.throws(() => db.run(`INSERT INTO roles (name, description) VALUES ('qa-temp','doublon')`), /UNIQUE/, 'nom de rôle unique, casse indépendante');
    assert.throws(() => db.run(`INSERT INTO roles (name, is_system) VALUES ('flag', 2)`), /CHECK/, 'is_system borné à 0/1');
    db.run(`DELETE FROM roles WHERE name='QA-temp'`);
    assert.throws(() => db.run(`INSERT INTO permissions (key, category) VALUES ('users:read','users')`), /UNIQUE/);
    assert.throws(
      () => db.run(`INSERT INTO user_roles (user_id, role_id) SELECT user_id, role_id FROM user_roles WHERE user_id=?`, [ctx.users.admin.id]),
      /UNIQUE/,
      'un rôle ne peut pas être attribué deux fois',
    );
  });

  it('seede un RBAC cohérent', () => {
    const db = ctx.runtime.db;
    const roles = db.all(`SELECT name FROM roles ORDER BY name`).map((r) => r.name);
    assert.deepEqual(roles, ['ADMIN', 'USER'], 'rôles de base');
    const counts = db.get(
      `SELECT (SELECT count(*) FROM permissions) AS p,
              (SELECT count(*) FROM role_permissions rp JOIN roles r ON r.id=rp.role_id WHERE r.name='ADMIN') AS a,
              (SELECT count(*) FROM role_permissions rp JOIN roles r ON r.id=rp.role_id WHERE r.name='USER') AS u`,
    );
    assert.equal(counts.p, counts.a, 'ADMIN porte toutes les permissions');
    assert.ok(counts.u > 0 && counts.u < counts.a, 'USER est restreint');
    const adminUser = db.get(`SELECT count(*) AS c FROM users u JOIN user_roles ur ON ur.user_id=u.id JOIN roles r ON r.id=ur.role_id WHERE r.name='ADMIN' AND u.deleted_at IS NULL`).c;
    assert.ok(adminUser >= 1, 'au moins un administrateur');
    const orphan = db.get(`SELECT count(*) AS c FROM role_permissions rp LEFT JOIN permissions p ON p.id=rp.permission_id WHERE p.id IS NULL`).c;
    assert.equal(orphan, 0, 'aucune permission orpheline');
  });

  it('conserve les fichiers téléversés après suppression logique de l’auteur', () => {
    const db = ctx.runtime.db;
    const before0 = db.get(`SELECT count(*) AS c FROM files`).c;
    const soft = db.run(`UPDATE users SET deleted_at=? WHERE id=?`, [new Date().toISOString(), ctx.users.user.id]);
    assert.equal(soft.changes, 1);
    assert.equal(db.get(`SELECT count(*) AS c FROM files`).c, before0, 'aucune suppression physique en cascade');
    assert.ok(db.get(`SELECT deleted_at FROM users WHERE id=?`, [ctx.users.user.id]).deleted_at, 'marqué supprimé');
    assert.ok(db.get(`SELECT status FROM users WHERE id=?`, [ctx.users.user.id]).status, 'la ligne reste interrogeable pour audit');
    db.run(`UPDATE users SET deleted_at=NULL WHERE id=?`, [ctx.users.user.id]);
  });

  it('passe l’intégrité et le mode WAL sur une base fichier', () => {
    const check = ctx.runtime.db.get(`PRAGMA integrity_check`).integrity_check;
    assert.equal(check, 'ok', 'aucune corruption');
    const mode = ctx.runtime.db.get(`PRAGMA journal_mode`).journal_mode;
    assert.ok(['wal', 'memory'].includes(String(mode).toLowerCase()), `mode journal ${mode}`);
    const violations = ctx.runtime.db.all(`PRAGMA foreign_key_check`);
    assert.equal(violations.length, 0, 'aucune clé étrangère violée');
  });
});

describe('couche d’accès', () => {
  it('normalise les paramètres avant SQLite', () => {
    assert.equal(normaliseParam(undefined), null);
    assert.equal(normaliseParam(true), 1);
    assert.equal(normaliseParam(false), 0);
    assert.equal(normaliseParam(null), null);
    assert.equal(normaliseParam(Number.NaN), null, 'NaN n’est pas un entier SQL');
    assert.equal(normaliseParam(new Date('2026-01-01T00:00:00.000Z')), '2026-01-01T00:00:00.000Z');
    assert.equal(normaliseParam(42n), 42n);
    assert.ok(Buffer.isBuffer(normaliseParam(Buffer.from('ab'))) || normaliseParam(Buffer.from('ab')) instanceof Uint8Array, 'les octets traversent intacts');
    assert.equal(normaliseParam(1.5), 1.5, 'un nombre fractionnaire est légal en SQL');
    assert.equal(normaliseParam({ a: 1 }), '[object Object]', 'jamais d’objet non sérialisé transmis tel quel : la couche appelante doit sérialiser');
  });

  it('convertit les bigint en nombres JS', () => {
    const out = normaliseRow({ id: 7n, name: 'x' });
    assert.equal(out.id, 7);
    assert.equal(normaliseRow(null), null);
  });

  it('exécute les transactions en atomicité', async () => {
    const ctx = await boot();
    try {
      const db = ctx.runtime.db;
      const before0 = db.get(`SELECT count(*) AS c FROM users`).c;
      assert.throws(() => {
        db.tx(() => {
          db.run(`INSERT INTO users (email, username, password_hash, hash_params) VALUES (?,?,?,?)`, ['tx@test.local', 'txuser', 'h', '{}']);
          throw new Error('échec simulé');
        });
      }, /échec simulé/);
      assert.equal(db.get(`SELECT count(*) AS c FROM users`).c, before0, 'aucune écriture conservée');
      db.tx(() => {
        db.run(`INSERT INTO users (email, username, password_hash, hash_params) VALUES (?,?,?,?)`, ['tx2@test.local', 'tx2user', 'h', '{}']);
        db.run(`INSERT INTO settings (key, value_json, value_type, is_public) VALUES (?,?,?,?)`, ['tx.probe', '"1"', 'int', 1]);
      });
      assert.ok(db.get(`SELECT id FROM users WHERE email='tx2@test.local'`), 'les deux écritures passent ensemble');
    } finally {
      await ctx.close();
    }
  });

  it('expose des helpers de lecture cohérents', async () => {
    const { db, dir } = freshDb();
    try {
      migrate(db, { dir: MIGRATIONS_DIR });
      const stmt = db.run(`INSERT INTO settings (key, value_json, value_type, is_public, updated_at) VALUES (?,?,?,?,?)`, ['probe.key', '"v"', 'string', 1, '2026-01-01T00:00:00Z']);
      assert.equal(stmt.changes, 1, 'écriture simple');
      assert.ok(Number(stmt.lastInsertRowid) >= 0 || stmt.lastInsertRowid === undefined || typeof stmt.lastInsertRowid === 'number', 'résultat d’écriture exploitable');
      assert.equal(db.get(`SELECT value_json FROM settings WHERE key='probe.key'`).value_json, '"v"');
      assert.equal(db.pluck(`SELECT key FROM settings ORDER BY key LIMIT 1`), 'agents.parallel_workers', 'pluck → premier scalaires de la première ligne');
      assert.equal(db.pluck(`SELECT key FROM settings WHERE key='absent'`), undefined, 'et undefined si rien ne correspond');
      assert.equal(db.exists(`SELECT 1 FROM settings WHERE key='probe.key'`), true);
      assert.equal(db.exists(`SELECT 1 FROM settings WHERE key='absent'`), false);
      assert.equal(db.all(`SELECT key FROM settings WHERE key='absent'`).length, 0);
      // Une requête invalide remonte l’erreur SQLite à l’appelant (et ne
      // retourne pas silencieusement un tableau vide).
      assert.throws(() => db.all(`SELECT * FROM table_inexistante`), /no such table/);
      // Les paramètres nommés et positionnels sont tous deux acceptés.
      assert.equal(db.get(`SELECT count(*) AS c FROM settings WHERE key = :k`, { k: 'probe.key' }).c, 1);
    } finally {
      db.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
