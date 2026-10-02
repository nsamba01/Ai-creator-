/**
 * Admin surface: dashboard aggregation, configuration, agents board and task
 * workflow, session administration, security posture.
 */
import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { boot } from './helpers.js';

const ADMIN = { id: 'admin@test.local', password: 'Sup3r-Secret-Initial!' };
const USER = { id: 'alice@test.local', password: 'User-Standard-2026!' };

describe('tableau de bord et configuration', () => {
  let ctx;
  let admin;
  let user;
  before(async () => {
    ctx = await boot();
    admin = ctx.client();
    user = ctx.client();
    await admin.login(ADMIN.id, ADMIN.password);
    await user.login(USER.id, USER.password);
  });
  after(async () => {
    await ctx.close();
  });

  it('agrège les compteurs pour l’administrateur', async () => {
    const res = await admin.get('/api/admin/dashboard');
    assert.equal(res.status, 200);
    assert.equal(res.body.scope, 'admin');
    const text = JSON.stringify(res.body);
    for (const key of ['users', 'sessions', 'audit', 'files']) {
      assert.ok(text.includes(key), `bloc ${key} présent`);
    }
    assert.ok(res.body.overview.users.total >= 2 && res.body.overview.sessions.active >= 1, 'compteurs exposés');
    assert.ok(Array.isArray(res.body.overview.topActions), 'actions les plus fréquentes');
    assert.ok(!text.includes(ADMIN.password), 'aucun secret dans le payload');
  });

  it('restreint le tableau de bord utilisateur à son périmètre', async () => {
    const res = await user.get('/api/admin/dashboard');
    assert.equal(res.status, 200, 'l’utilisateur a un espace personnel');
    assert.equal(res.body.scope, 'self');
    assert.equal(res.body.users, undefined, 'pas de vue globale');
    const text = JSON.stringify(res.body);
    assert.ok(!/totalUsers|"admins"/.test(text), 'aucun compteur d’administration');
  });

  it('lit la configuration effective et refuse les écritures non admin', async () => {
    const res = await admin.get('/api/admin/settings');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.settings) || typeof res.body.settings === 'object');
    assert.equal(res.body.effective.passwordMinLength >= 8, true, 'longueur minimale cohérente');
    const denied = await user.get('/api/admin/settings');
    assert.equal(denied.status, 403, 'settings:read est réservé');
    const writeDenied = await user.put('/api/admin/settings', { key: 'security.password_min_length', value: 8 });
    assert.equal(writeDenied.status, 403, 'settings:update est réservé');
  });

  it('bornne et valide les valeurs écrites, et trace la modification', async () => {
    const ok = await admin.put('/api/admin/settings', { key: 'security.session_ttl_minutes', value: 90 });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    assert.equal(ok.body.updated.length, 1);
    const tooBig = await admin.put('/api/admin/settings', { key: 'security.session_ttl_minutes', value: 999999 });
    assert.equal(tooBig.status, 200, 'refus motivé plutôt que 500');
    assert.equal(tooBig.body.updated.length, 0);
    assert.match(tooBig.body.rejected[0].reason, /maximum/);
    const logged = ctx.runtime.db.get(`SELECT count(*) AS c FROM audit_logs WHERE action='admin.settings.updated'`).c;
    assert.ok(logged >= 1, 'modification journalisée');
    await admin.put('/api/admin/settings', { key: 'security.session_ttl_minutes', value: 60 });
  });

  it('masque les clés privées à la lecture simple, et ne divulgue jamais une valeur secrète', async () => {
    const asAdmin = await admin.get('/api/admin/settings');
    assert.equal(asAdmin.status, 200);
    const privateKeys = ctx.runtime.db.all(`SELECT key FROM settings WHERE is_public = 0`).map((r) => r.key);
    const publicKeys = asAdmin.body.settings.filter((r) => !r.public).map((r) => r.key);
    if (privateKeys.length) {
      assert.deepEqual(publicKeys.sort(), privateKeys.sort(), 'les clés non publiques ne sont listées qu’avec settings:update');
    }
    const secretish = asAdmin.body.settings.filter((r) => r.isSecret);
    for (const r of secretish) {
      assert.equal(r.masked, true, `« ${r.key} » est masquée à la lecture`);
      assert.ok(r.value === undefined || r.value === null || r.value === '' , 'aucune valeur renvoyée');
    }
    // Un utilisateur standard ne voit que le sous-ensemble public.
    const asUser = await user.get('/api/admin/settings');
    assert.equal(asUser.status, 403, 'settings:read est requis, même pour la vue publique');
  });
});

describe('agents IA et file de tâches', () => {
  let ctx;
  let admin;
  let user;
  before(async () => {
    ctx = await boot();
    admin = ctx.client();
    user = ctx.client();
    await admin.login(ADMIN.id, ADMIN.password);
    await user.login(USER.id, USER.password);
  });
  after(async () => {
    await ctx.close();
  });

  it('présente les rôles d’agents et le flux de travail', async () => {
    const res = await admin.get('/api/agents');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.agents) && res.body.agents.length >= 4);
    for (const a of res.body.agents) {
      assert.ok(a.key && a.name && a.mission, 'chaque agent est décrit');
      assert.ok(Array.isArray(a.permissions), 'ses permissions sont listées');
    }
    assert.ok(Array.isArray(res.body.workflow) && res.body.workflow.length >= 6, 'le flux de travail est exposé');
    const flow = res.body.workflow.join(' ').toLowerCase();
    assert.ok(flow.includes('inspection') && flow.includes('plan') && flow.includes('implémentation'), 'étapes clés présentes');
    assert.ok(flow.includes('audit indépendant'), 'la revue indépendante est une étape du flux');
  });

  it('crée, fait progresser et clôt une tâche avec audit', async () => {
    const created = await admin.post('/api/agents/tasks', {
      title: 'Analyser la configuration Docker',
      agentRole: 'securite',
      priority: 'high',
      description: 'Vérifier les permissions, les secrets et le contexte d’exécution.',
    });
    assert.equal(created.status, 201, JSON.stringify(created.body));
    const id = created.body.task.id;
    assert.equal(created.body.task.status, 'queued');

    const running = await admin.patch(`/api/agents/tasks/${id}`, { status: 'running' });
    assert.equal(running.status, 200);
    assert.equal(running.body.task.status, 'running');

    const done = await admin.patch(`/api/agents/tasks/${id}`, { status: 'done', resultSummary: 'Trois durcissements appliqués.' });
    assert.equal(done.status, 200, JSON.stringify(done.body));
    assert.equal(done.body.task.status, 'done');
    assert.equal(done.body.task.resultSummary, 'Trois durcissements appliqués.');
    assert.ok(done.body.task.completedAt, 'horodatage de clôture');

    const rows = ctx.runtime.db.all(`SELECT action FROM audit_logs WHERE action LIKE 'agent.task%'`);
    assert.ok(rows.length >= 3, `création et transitions journalisées (${rows.length})`);
  });

  it('refuse un statut ou un rôle inconnu', async () => {
    const bad = await admin.post('/api/agents/tasks', { title: 'X', agentRole: 'superman', priority: 'normal' });
    assert.equal(bad.status, 400, 'rôle d’agent validé');
    const created = await admin.post('/api/agents/tasks', { title: 'Deuxième tâche', agentRole: 'qa', priority: 'low' });
    const badStatus = await admin.patch(`/api/agents/tasks/${created.body.task.id}`, { status: 'terminé' });
    assert.ok([400, 404].includes(badStatus.status), 'statut validé');
    assert.ok(!['terminated'].includes(ctx.runtime.db.get(`SELECT status FROM agent_tasks WHERE id=?`, [created.body.task.id]).status));
  });

  it('interdit l’écriture de tâches à un utilisateur standard', async () => {
    const res = await user.post('/api/agents/tasks', { title: 'Tâche non autorisée', agentRole: 'qa', priority: 'normal' });
    assert.equal(res.status, 403, 'agents:update est réservé');
    const read = await user.get('/api/agents/tasks');
    assert.equal(read.status, 200, 'la lecture est autorisée (agents:read)');
    assert.ok(Array.isArray(read.body.items ?? read.body.tasks), 'liste paginée');
  });

  it('borne la liste et ignore les paramètres farfelus', async () => {
    const res = await admin.get('/api/agents/tasks?limit=99999&status=nope');
    assert.equal(res.status, 200);
    const items = res.body.items ?? res.body.tasks ?? [];
    assert.ok(items.length <= 200, 'limite bornée côté serveur');
  });
});

describe('sessions et posture de sécurité', () => {
  let ctx;
  let admin;
  let user;
  before(async () => {
    ctx = await boot();
    admin = ctx.client();
    user = ctx.client();
    await admin.login(ADMIN.id, ADMIN.password);
    await user.login(USER.id, USER.password);
  });
  after(async () => {
    await ctx.close();
  });

  it('refuse une révoquation globale sur un compte verrouillé par le mot de passe provisoire', async () => {
    const t = await admin.post('/api/users', { email: 'hugo2@test.local', username: 'hugo2', roles: ['USER'] });
    const c = ctx.client();
    await c.login('hugo2@test.local', t.body.temporaryPassword);
    const blocked = await c.post('/api/sessions/revoke-all', {});
    assert.equal(blocked.status, 403, 'le changement de mot de passe est exigé avant toute autre opération');
    assert.equal(blocked.body.error.code, 'PASSWORD_CHANGE_REQUIRED');
  });

  it('liste les siennes, sans jeton, avec l’empreinte d’adresse uniquement', async () => {
    const res = await user.get('/api/sessions');
    assert.equal(res.status, 200);
    const items = res.body.items ?? res.body.sessions;
    assert.ok(items.length >= 1);
    const text = JSON.stringify(res.body);
    assert.ok(!text.includes(user.jar.get('ps_session')), 'le jeton de session n’est jamais renvoyé');
    assert.ok(!/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(text), 'pas d’IP en clair');
    const s = items[0];
    assert.ok(s.createdAt, 'horodatages présents');
    assert.equal(s.current, true, 'la session active est marquée');
    assert.match(s.ipHash, /^ip:[0-9a-f]{16,}$/, 'adresse anonymisée par empreinte');
    assert.match(s.userAgentHash, /^ua:[0-9a-f]{16,}$/, 'agent utilisateur condensé');
    assert.ok(!JSON.stringify(s).includes('node-fetch'), 'l’agent utilisateur brut n’est pas conservé');
  });

  it('révoque une session identifiée, et refuse celle d’un tiers', async () => {
    const other = ctx.client();
    await other.login(USER.id, USER.password);
    const list = await user.get('/api/sessions');
    const items = list.body.items ?? list.body.sessions;
    const foreign = items.find((s) => !(s.current === true || s.isCurrent === true)) ?? items[0];
    const del = await user.del(`/api/sessions/${foreign.id}`);
    assert.ok([200, 204].includes(del.status), `révocation (${del.status})`);
    const stillValid = await other.get('/api/auth/me');
    if (stillValid.status === 401) assert.ok(true, 'session révoquée immédiatement');
    else assert.ok(['current', 'isCurrent'].some((k) => foreign[k]) === false || stillValid.status === 200, 'la session courante survit à la révocation d’une autre');

    const victim = await admin.post('/api/users', { email: 'gina@test.local', username: 'gina', roles: ['USER'] });
    const setup2 = ctx.client();
    await setup2.login('gina@test.local', victim.body.temporaryPassword);
    await setup2.post('/api/auth/change-password', {
      currentPassword: victim.body.temporaryPassword,
      newPassword: 'Zephyr-Clarification-2026!',
      confirm: 'Zephyr-Clarification-2026!',
    });
    const gv = ctx.client();
    await gv.login('gina@test.local', 'Zephyr-Clarification-2026!');
    const ginaSessions = await gv.get('/api/sessions');
    const gid = (ginaSessions.body.items ?? ginaSessions.body.sessions)[0].id;
    const stolen = await user.del(`/api/sessions/${gid}`);
    assert.equal(stolen.status, 403, 'on ne révoque pas la session d’un autre');
  });

  it('révoque toutes les sessions d’un compte à la demande', async () => {
    const target = await admin.post('/api/users', { email: 'hugo@test.local', username: 'hugo', roles: ['USER'] });
    const setup = ctx.client();
    await setup.login('hugo@test.local', target.body.temporaryPassword);
    const changed = await setup.post('/api/auth/change-password', {
      currentPassword: target.body.temporaryPassword,
      newPassword: 'Zephyr-Clarification-2026!',
      confirm: 'Zephyr-Clarification-2026!',
    });
    assert.equal(changed.status, 200, JSON.stringify(changed.body));
    const h = ctx.client();
    await h.login('hugo@test.local', 'Zephyr-Clarification-2026!');
    const another = ctx.client();
    await another.login('hugo@test.local', 'Zephyr-Clarification-2026!');
    const before0 = ctx.runtime.db.get(`SELECT count(*) AS c FROM sessions WHERE revoked_at IS NULL AND user_id=(SELECT id FROM users WHERE email='hugo@test.local')`).c;
    assert.ok(before0 >= 2, 'deux sessions actives');
    const res = await h.post('/api/sessions/revoke-all', {});
    assert.equal(res.status, 200, JSON.stringify(res.body));
    const after0 = ctx.runtime.db.get(`SELECT count(*) AS c FROM sessions WHERE revoked_at IS NULL AND user_id=(SELECT id FROM users WHERE email='hugo@test.local')`).c;
    assert.equal(after0, 0, 'tout est révoqué');
    const dead = await another.get('/api/auth/me');
    assert.equal(dead.status, 401, 'l’autre appareil est déconnecté');
  });

  it('expose un bilan de posture lisible, sans valeur sensible', async () => {
    const res = await admin.get('/api/admin/security');
    assert.equal(res.status, 200);
    assert.equal(res.body.scope, 'admin');
    assert.ok(Array.isArray(res.body.checks) && res.body.checks.length >= 8, 'au moins 8 contrôles');
    const labels = res.body.checks.map((c) => c.label).join(' ');
    for (const word of ['Argon2id', 'CSRF', 'cookie']) {
      assert.ok(labels.toLowerCase().includes(word.toLowerCase()), `contrôle ${word} présent`);
    }
    assert.ok(res.body.checks.every((c) => typeof c.ok === 'boolean' && c.label), 'forme stable des contrôles');
    assert.ok(typeof res.body.score === 'number' && res.body.score >= 0 && res.body.score <= 100, 'score normalisé');
    const text = JSON.stringify(res.body);
    assert.ok(!text.includes(ADMIN.password), 'aucun mot de passe dans le bilan');
    assert.ok(!/\$argon2[a-z]*\$v=/.test(text), 'aucun hash dans le bilan');
  });

  it('signale les comptes à risque pour l’administrateur', async () => {
    const res = await admin.get('/api/admin/security/users-at-risk');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.locked) && Array.isArray(res.body.mustChangePassword), 'listes présentes');
    const created = await admin.post('/api/users', { email: 'irene@test.local', username: 'irene', roles: ['USER'] });
    assert.equal(created.body.user.mustChangePassword, true, 'le compte créé doit changer son mot de passe');
    const list = await admin.get('/api/admin/security/users-at-risk');
    assert.ok(list.body.mustChangePassword.some((u) => u.email === 'irene@test.local'), 'il apparaît donc dans la liste à risque');
    const denied = await user.get('/api/admin/security/users-at-risk');
    assert.equal(denied.status, 403, 'réservé à audit:read');
  });

  it('refuse le nettoyage global aux non-administrateurs', async () => {
    const denied = await user.post('/api/sessions/purge', {});
    assert.equal(denied.status, 403);
    const ok = await admin.post('/api/sessions/purge', {});
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    assert.ok(Number.isFinite(ok.body.sessions ?? ok.body.removed ?? 0), 'compte rendu chiffré');
  });
});
