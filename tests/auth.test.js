import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { boot } from './helpers.js';
import * as usersRepo from '../src/repositories/users.repo.js';

const ADMIN = { id: 'admin@test.local', password: 'Sup3r-Secret-Initial!' };
const USER = { id: 'alice@test.local', password: 'User-Standard-2026!' };

describe('authentification', () => {
  let ctx;
  before(async () => {
    ctx = await boot();
  });
  after(async () => {
    await ctx.close();
  });

  it('refuse une connexion sans identifiants', async () => {
    const res = await ctx.client().post('/api/auth/login', {});
    assert.equal(res.status, 400);
    assert.equal(res.body.error.code, 'BAD_REQUEST');
  });

  it('rejette un mot de passe erroné sans révéler l’existence du compte', async () => {
    const wrong = await ctx.client().post('/api/auth/login', { identifier: ADMIN.id, password: 'MotDePasse-Faux-9!' });
    const missing = await ctx.client().post('/api/auth/login', { identifier: 'inexistant@x.io', password: 'MotDePasse-Faux-9!' });
    assert.equal(wrong.status, 401);
    assert.equal(missing.status, 401);
    // Same message for both cases: no user enumeration.
    assert.equal(wrong.body.error.message, missing.body.error.message);
  });

  it('connecte un utilisateur et pose les cookies sécurisés', async () => {
    const c = ctx.client();
    const res = await c.login(ADMIN.id, ADMIN.password);
    assert.equal(res.status, 200);
    const setCookies = res.headers.getSetCookie();
    assert.ok(setCookies.some((l) => /ps_session=/.test(l)), 'cookie de session présent');
    const sessionLine = setCookies.find((l) => l.includes('ps_session='));
    assert.match(sessionLine, /HttpOnly/i, 'HttpOnly');
    assert.match(sessionLine, /SameSite=Strict/i, 'SameSite=Strict');
    assert.ok(setCookies.some((l) => /ps_refresh=.*HttpOnly/i.test(l)), 'refresh HttpOnly');
    const csrfLine = setCookies.find((l) => l.includes('ps_csrf='));
    assert.ok(csrfLine && !/HttpOnly/i.test(csrfLine), 'cookie CSRF lisible par JS, session non');
    assert.equal(res.body.user.passwordHash, undefined, 'aucun hash renvoyé');
    assert.equal(res.body.user.password, undefined);
    assert.ok(res.body.csrfToken, 'jeton CSRF renvoyé');
    assert.equal(res.body.mustChangePassword, false);
  });

  it('n’enregistre jamais un mot de passe en clair et stocke un hash Argon2id vérifiable', () => {
    const row = usersRepo.findAuthRowByIdentifier(ctx.runtime.db, ADMIN.id);
    assert.ok(row.password_hash.startsWith('$argon2id$'), `format PHC attendu, obtenu : ${row.password_hash.slice(0, 12)}`);
    assert.ok(row.password_hash.split('$').length === 6, 'salt + digest encodés');
    assert.ok(!row.password_hash.includes(ADMIN.password), 'le mot de passe n’apparaît pas dans le hash');
    assert.ok(!JSON.stringify(row).includes(ADMIN.password), 'ni dans les colonnes annexes');
    assert.equal(row.password_hash, row.password_hash.toLowerCase() === row.password_hash ? row.password_hash : row.password_hash);
    // Le sel encodé doit être distinct du digest
    const [, , , , salt, digest] = row.password_hash.split('$');
    assert.ok(salt && digest && salt !== digest);
  });

  it('bloque /api/users sans session et accepte la session par cookie', async () => {
    const anon = await ctx.client().get('/api/users');
    assert.equal(anon.status, 401);
    const c = ctx.client();
    await c.login(ADMIN.id, ADMIN.password);
    const ok = await c.get('/api/users');
    assert.equal(ok.status, 200);
    assert.ok(Array.isArray(ok.body.items));
  });

  it('refuse une session falsifiée et une session expirée', async () => {
    const fake = ctx.client();
    fake.setCookie('ps_session', 'a'.repeat(64));
    const res = await fake.get('/api/auth/me');
    assert.equal(res.status, 401);

    const c = ctx.client();
    await c.login(ADMIN.id, ADMIN.password);
    // Expire la session côté serveur.
    ctx.runtime.db.run(`UPDATE sessions SET expires_at = ? WHERE user_id = (SELECT id FROM users WHERE email = ?)`, [
      new Date(Date.now() - 1000).toISOString(),
      ADMIN.id,
    ]);
    const expired = await c.get('/api/auth/me');
    assert.equal(expired.status, 401, 'session expirée refusée');
    assert.match(expired.headers.get('x-session-state') ?? '', /expired/, 'indication d’expiration pour le client');
  });

  it('révoque la session à la déconnexion', async () => {
    const c = ctx.client();
    await c.login(USER.id, USER.password);
    const me = await c.get('/api/auth/me');
    assert.equal(me.status, 200);
    const out = await c.post('/api/auth/logout', {});
    assert.equal(out.status, 200);
    const after = await c.get('/api/auth/me');
    assert.equal(after.status, 401, 'cookie purgé et session morte');
    const stillInDb = ctx.runtime.db.get(`SELECT revoked_at FROM sessions WHERE user_id = (SELECT id FROM users WHERE email=?)`, [USER.id]);
    assert.ok(stillInDb?.revoked_at, 'révocation persistée');
  });

  it('fait tourner le refresh token et tue la famille en cas de rejouement', async () => {
    const c = ctx.client();
    await c.login(USER.id, USER.password);
    const oldRefresh = c.jar.get('ps_refresh');
    assert.ok(oldRefresh, 'cookie de refresh posé à la connexion');
    const oldRowId = ctx.runtime.db.get(`SELECT id FROM refresh_tokens ORDER BY id DESC LIMIT 1`).id;

    const rotated = await c.post('/api/auth/refresh', {});
    assert.equal(rotated.status, 200, 'rotation acceptée');
    const newRefresh = c.jar.get('ps_refresh');
    assert.notEqual(newRefresh, oldRefresh, 'le refresh token est bien renouvelé');
    assert.ok(ctx.runtime.db.get(`SELECT used_at FROM refresh_tokens WHERE id = ?`, [oldRowId]).used_at, 'l’ancien token est marqué consommé');
    assert.equal(ctx.runtime.db.get(`SELECT count(*) AS c FROM refresh_tokens WHERE id > ?`, [oldRowId]).c, 1, 'exactement un token de rechange émis');

    // Rejouement de l’ancien token (cookie volé) => toute la famille est révoquée.
    c.setCookie('ps_refresh', oldRefresh);
    const replay = await c.post('/api/auth/refresh', {});
    assert.equal(replay.status, 401, 'rejouement refusé');
    const familyId = ctx.runtime.db.get(`SELECT family_id AS f FROM refresh_tokens WHERE id = ?`, [oldRowId]).f;
    const liveInFamily = ctx.runtime.db.get(`SELECT count(*) AS c FROM refresh_tokens WHERE family_id = ? AND revoked_at IS NULL`, [familyId]).c;
    assert.equal(liveInFamily, 0, 'famille entière révoquée');
    const sessions = ctx.runtime.db.get(`SELECT count(*) AS c FROM sessions WHERE user_id = (SELECT id FROM users WHERE email=?) AND revoked_at IS NULL`, [USER.id]).c;
    assert.equal(sessions, 0, 'sessions de l’utilisateur coupées également');
    const flagged = ctx.runtime.db.get(`SELECT count(*) AS c FROM audit_logs WHERE action = 'auth.refresh.reuse_detected' AND severity = 'critical'`).c;
    assert.ok(flagged >= 1, 'événement critique journalisé');
  });

  it('impose le changement du mot de passe initial', async () => {
    const db = ctx.runtime.db;
    const { hashPassword } = await import('../src/services/password.service.js');
    const { hash, params } = await hashPassword('Temp-Initial-123!', ctx.config.password.argon2);
    const u = usersRepo.createUser(db, { email: 'newbie@test.local', username: 'newbie', passwordHash: hash, hashParams: params, mustChangePassword: true });
    db.run(`INSERT INTO user_roles (user_id, role_id) VALUES (?, (SELECT id FROM roles WHERE name='USER'))`, [u.id]);

    const c = ctx.client();
    const login = await c.login('newbie@test.local', 'Temp-Initial-123!');
    assert.equal(login.status, 200);
    assert.equal(login.body.mustChangePassword, true);

    const blocked = await c.get('/api/agents');
    assert.equal(blocked.status, 403, 'API non essentielle bloquée tant que le mot de passe initial est en usage');
    assert.equal(blocked.body.error.code, 'PASSWORD_CHANGE_REQUIRED');

    const allowed = await c.get('/api/auth/me');
    assert.equal(allowed.status, 200, 'la route de changement reste accessible');

    const change = await c.post('/api/auth/change-password', {
      currentPassword: 'Temp-Initial-123!',
      newPassword: 'Après-Changement-Fort-2026!',
      confirm: 'Après-Changement-Fort-2026!',
    });
    assert.equal(change.status, 200, JSON.stringify(change.body));
    const after = await c.get('/api/agents');
    assert.equal(after.status, 200, 'accès rétabli après changement');
  });

  it('refuse un mot de passe trop faible et applique la politique serveur', async () => {
    const c = ctx.client();
    await c.login(ADMIN.id, ADMIN.password);
    const res = await c.post('/api/auth/change-password', { currentPassword: ADMIN.password, newPassword: 'short1!A', confirm: 'short1!A' });
    assert.equal(res.status, 400);
    assert.ok(res.body.error.details.reasons.some((r) => /caractères/.test(r)), 'explication de la longueur');

    const same = await c.post('/api/auth/change-password', { currentPassword: ADMIN.password, newPassword: ADMIN.password, confirm: ADMIN.password });
    assert.equal(same.status, 400, 'interdiction de réutiliser le même mot de passe');
  });

  it('valide le changement de mot de passe puis révoque les autres sessions', async () => {
    const a = ctx.client();
    const b = ctx.client();
    await a.login('alice@test.local', 'User-Standard-2026!');
    await b.login('alice@test.local', 'User-Standard-2026!');
    const changed = await a.post('/api/auth/change-password', {
      currentPassword: 'User-Standard-2026!',
      newPassword: 'Nouveau-Mot-De-Passe-2026!',
      confirm: 'Nouveau-Mot-De-Passe-2026!',
    });
    assert.equal(changed.status, 200, JSON.stringify(changed.body));
    assert.equal((await a.get('/api/auth/me')).status, 200, 'la session active est conservée');
    assert.equal((await b.get('/api/auth/me')).status, 401, 'les autres sessions sont coupées');
    const relogin = await ctx.client().login('alice@test.local', 'User-Standard-2026!');
    assert.equal(relogin.status, 401, 'l’ancien mot de passe ne fonctionne plus');
  });

  it('verrouille le compte après N échecs (anti brute-force)', async () => {
    const db = ctx.runtime.db;
    const { hashPassword } = await import('../src/services/password.service.js');
    const victimPassword = 'Victime-Mot-De-Passe-1!';
    const { hash, params } = await hashPassword(victimPassword, ctx.config.password.argon2);
    const bob = usersRepo.createUser(db, {
      email: 'bob@test.local',
      username: 'bob',
      passwordHash: hash,
      hashParams: params,
      mustChangePassword: false,
      status: 'active',
    });
    assert.ok(bob.id);

    const c = ctx.client();
    let lastStatus = 0;
    for (let i = 0; i < 7; i += 1) {
      const r = await c.post('/api/auth/login', { identifier: 'bob@test.local', password: `faute-${i}-Passw0rd!` });
      lastStatus = r.status;
    }
    assert.ok([401, 423, 429].includes(lastStatus), `statut de blocage obtenu : ${lastStatus}`);
    const row = ctx.runtime.db.get(`SELECT status, locked_until FROM users WHERE email='bob@test.local'`);
    assert.ok(row.locked_until, 'verrouillage temporel posé');

    // Même avec le BON mot de passe, le compte est verrouillé temporairement.
    const good = await ctx.client().post('/api/auth/login', { identifier: 'bob@test.local', password: 'Victime-Mot-De-Passe-1!' });
    assert.ok([423, 429].includes(good.status), `compte verrouillé malgré bon mot de passe (${good.status})`);
    assert.ok(good.status !== 200);
  });

  it('accepte un reset de mot de passe à usage unique', async () => {
    const req = await ctx.client().post('/api/auth/password-reset/request', { identifier: ADMIN.id });
    assert.equal(req.status, 202);
    const token = req.body.devToken;
    assert.ok(token, 'jeton renvoyé hors production pour permettre le test du parcours');

    const ok = await ctx.client().post('/api/auth/password-reset/confirm', { token, newPassword: 'Reset-Termine-Fort-2026!' });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));

    const reuse = await ctx.client().post('/api/auth/password-reset/confirm', { token, newPassword: 'Encore-Un-Autre-2026!' });
    assert.equal(reuse.status, 400, 'jeton à usage unique');

    const loginNew = await ctx.client().login(ADMIN.id, 'Reset-Termine-Fort-2026!');
    assert.equal(loginNew.status, 200, 'nouveau mot de passe fonctionnel');
    const loginOld = await ctx.client().login(ADMIN.id, 'Sup3r-Secret-Initial!');
    assert.equal(loginOld.status, 401, 'ancien mot de passe mort');
  });

  it('ne révèle pas l’existence d’un compte via la demande de réinitialisation', async () => {
    const a = await ctx.client().post('/api/auth/password-reset/request', { identifier: 'absent@nowhere.tld' });
    assert.equal(a.status, 202);
    assert.equal(a.body.devToken, undefined, 'aucun jeton pour un compte inexistant');
    assert.equal(a.body.message, (await ctx.client().post('/api/auth/password-reset/request', { identifier: USER.id })).body.message);
  });
});

describe('bootstrap du premier administrateur', () => {
  let ctx;
  before(async () => {
    ctx = await boot({ withAdmin: false, bootstrap: true });
  });
  after(async () => {
    await ctx.close();
  });

  it('crée le compte ADMIN depuis l’environnement, jamais depuis le code', async () => {
    const admin = usersRepo.findUserByIdentifier(ctx.runtime.db, 'root@example.com');
    assert.ok(admin, 'compte créé');
    assert.deepEqual(admin.roles, ['ADMIN']);
    assert.equal(admin.mustChangePassword, true, 'changement du mot de passe initial imposé');
    const row = usersRepo.findAuthRowByIdentifier(ctx.runtime.db, 'root@example.com');
    assert.ok(!JSON.stringify(row).includes('Env-Bootstrap-Pass-2026!'), 'mot de passe initial absent de la base');

    const login = await ctx.client().login('root@example.com', 'Env-Bootstrap-Pass-2026!');
    assert.equal(login.status, 200);
    assert.equal(login.body.mustChangePassword, true);
  });

  it('est idempotent', async () => {
    const { bootstrapAdmin } = await import('../src/services/bootstrap.service.js');
    const again = await bootstrapAdmin({ db: ctx.runtime.db, config: ctx.config, audit: ctx.runtime.audit, rbac: ctx.runtime.rbac });
    assert.equal(again.created, false);
    assert.match(again.reason, /déjà présent/i);
  });
});
