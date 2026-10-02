/**
 * RBAC : la règle fondamentale du cahier des charges est qu’un utilisateur
 * standard ne peut PAS créer d’utilisateurs, et que le contrôle est serveur.
 * Ces tests vérifient les réponses HTTP réelles, pas l’interface.
 */
import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { boot } from './helpers.js';

const ADMIN = { id: 'admin@test.local', password: 'Sup3r-Secret-Initial!' };
const USER = { id: 'alice@test.local', password: 'User-Standard-2026!' };

describe('RBAC et séparation ADMIN / USER', () => {
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

  it('définit la matrice attendue en base', () => {
    const adminPerms = ctx.runtime.rbac.permissionsOf(ctx.users.admin.id);
    const userPerms = ctx.runtime.rbac.permissionsOf(ctx.users.user.id);
    for (const p of ['users:create', 'users:read', 'users:update', 'users:disable', 'users:delete', 'users:reset_password', 'roles:update', 'settings:update', 'audit:read', 'admin:access']) {
      assert.ok(adminPerms.has(p), `ADMIN doit détenir ${p}`);
      assert.ok(!userPerms.has(p), `USER ne doit PAS détenir ${p}`);
    }
    for (const p of ['files:create', 'documents:analyze', 'urls:analyze', 'agents:read', 'dashboard:read']) {
      assert.ok(userPerms.has(p), `USER doit conserver ${p} (auto-service)`);
    }
    assert.ok(!userPerms.has('files:read:any'), 'USER ne lit pas les fichiers d’autrui');
    assert.ok(!userPerms.has('sessions:revoke:any'), 'USER ne révoque pas les sessions d’autrui');
  });

  it('refuse la création d’utilisateur par un compte standard', async () => {
    const res = await user.post('/api/users', { email: 'victime@x.io', username: 'victime', roles: ['USER'] });
    assert.equal(res.status, 403);
    assert.match(res.body.error.message, /users:create/);
    assert.equal(ctx.runtime.db.get(`SELECT count(*) AS c FROM users WHERE email='victime@x.io'`).c, 0, 'aucune ligne créée');
  });

  it('refuse la lecture de la liste des utilisateurs par un compte standard', async () => {
    const res = await user.get('/api/users');
    assert.equal(res.status, 403);
  });

  it('refuse l’accès à l’audit, aux rôles et à la configuration', async () => {
    for (const path of ['/api/admin/audit', '/api/roles', '/api/permissions', '/api/admin/settings', '/api/admin/security/users-at-risk']) {
      const res = await user.get(path);
      assert.equal(res.status, 403, `${path} ne doit pas être lisible par un USER`);
    }
  });

  it('autorise l’auto-service pour un compte standard', async () => {
    const me = await user.get('/api/me');
    assert.equal(me.status, 200);
    const sessions = await user.get('/api/sessions');
    assert.equal(sessions.status, 200);
    assert.equal(sessions.body.scope, 'own', 'portée limitée à ses propres sessions');
    const agents = await user.get('/api/agents');
    assert.equal(agents.status, 200);
  });

  it('refuse l’écriture sur le tableau des agents', async () => {
    const res = await user.post('/api/agents/tasks', { title: 'Tâche non autorisée', agentRole: 'developpeur' });
    assert.equal(res.status, 403);
    const ok = await admin.post('/api/agents/tasks', { title: 'Tâche autorisée', agentRole: 'qa', priority: 'high' });
    assert.equal(ok.status, 201, 'l’administrateur peut piloter le tableau');
  });

  it('journalise chaque refus d’autorisation', async () => {
    const before = ctx.runtime.db.get(`SELECT count(*) AS c FROM audit_logs WHERE action='security.authorization.denied'`).c;
    await user.get('/api/users');
    await user.del('/api/users/1');
    const after = ctx.runtime.db.get(`SELECT count(*) AS c FROM audit_logs WHERE action='security.authorization.denied'`).c;
    assert.ok(after >= before + 2, `refus journalisés (${before} -> ${after})`);
    const last = ctx.runtime.db.get(`SELECT detail_json AS d FROM audit_logs WHERE action='security.authorization.denied' ORDER BY id DESC LIMIT 1`).d;
    assert.match(last, /users:read|users:delete/, 'le motif manquant est tracé');
  });

  it('crée un utilisateur, laisse l’administrateur lui attribuer des rôles, sans jamais exposer le hash', async () => {
    const created = await admin.post('/api/users', { email: 'carol@test.local', username: 'carol', displayName: 'Carol', roles: ['USER'] });
    assert.equal(created.status, 201, JSON.stringify(created.body));
    assert.ok(created.body.temporaryPassword, 'mot de passe temporaire généré côté serveur');
    assert.equal(created.body.user.passwordHash, undefined);
    assert.equal(JSON.stringify(created.body).includes(created.body.temporaryPassword), true, 'transmis une seule fois');

    const detail = await admin.get(`/api/users/${created.body.user.id}`);
    assert.equal(detail.status, 200);
    assert.ok(!JSON.stringify(detail.body).includes('$argon2id$'), 'le hash ne remonte jamais dans l’API');
    assert.ok(!JSON.stringify(detail.body).includes(created.body.temporaryPassword), 'le mot de passe temporaire n’est pas relisible');

    // L’utilitaire peut se connecter avec le mot de passe temporaire.
    const carol = ctx.client();
    const login = await carol.login('carol@test.local', created.body.temporaryPassword);
    assert.equal(login.status, 200);
    assert.equal(login.body.mustChangePassword, true, 'changement imposé à la première connexion');
  });

  it('interdit à un utilisateur standard de se promouvoir ADMIN', async () => {
    const res = await user.patch(`/api/users/${ctx.users.user.id}`, { roles: ['ADMIN'] });
    assert.equal(res.status, 403, 'ni la permission users:update, ni l’accès à ses propres rôles');
    const roles = ctx.runtime.rbac.rolesOf(ctx.users.user.id).map((r) => r.name);
    assert.deepEqual(roles, ['USER'], 'rôles inchangés en base');
  });

  it('empêche le verrouillage administratif (dernier ADMIN protégé)', async () => {
    const dave = await admin.post('/api/users', { email: 'dave@test.local', username: 'dave', roles: ['ADMIN'] });
    assert.equal(dave.status, 201);
    const admins = () =>
      ctx.runtime.db.get(
        `SELECT count(*) AS c FROM users u JOIN user_roles ur ON ur.user_id=u.id JOIN roles r ON r.id=ur.role_id
          WHERE r.name='ADMIN' AND u.deleted_at IS NULL AND u.status IN ('active','pending_password')`,
      ).c;
    assert.equal(admins(), 2, 'un second administrateur a été créé explicitement');

    // Un compte qui tente de se rétrograder lui-même est bloqué (403) : c’est
    // un garde-fou contre l’auto-escalade comme contre l’auto-verrouillage.
    const selfDemote = await admin.patch(`/api/users/${ctx.users.admin.id}`, { roles: ['USER'] });
    assert.equal(selfDemote.status, 403, 'pas d’auto-modification de rôles');

    // Auto-désactivation refusée (400) pour ne pas se couper la branche.
    const selfDisable = await admin.post(`/api/users/${ctx.users.admin.id}/status`, { status: 'disabled' });
    assert.equal(selfDisable.status, 400);

    // On retire le 2e admin : il ne reste qu’un ADMIN ; le retrait du rôle doit être refusé.
    const del = await admin.del(`/api/users/${dave.body.user.id}`);
    assert.equal(del.status, 200);
    assert.equal(admins(), 1, 'un seul administrateur restant');
    const demote = await admin.post(`/api/users/${ctx.users.admin.id}/roles`, { roles: ['USER'] });
    assert.equal(demote.status, 409, 'dernier administrateur : retrait du rôle refusé');
    const disable = await admin.post(`/api/users/${ctx.users.user.id}/status`, { status: 'disabled', reason: 'test' });
    assert.equal(disable.status, 200, 'désactiver un compte standard reste possible');
    const disabledUserSession = await user.get('/api/auth/me');
    assert.equal(disabledUserSession.status, 401, 'les sessions du compte désactivé sont coupées');
    await admin.post(`/api/users/${ctx.users.user.id}/status`, { status: 'active', reason: 'réactivation de test' });
    await user.login(USER.id, USER.password);
  });

  it('révoque les sessions lorsqu’un rôle change', async () => {
    const before = ctx.runtime.db.get(`SELECT count(*) AS c FROM sessions WHERE user_id = ? AND revoked_at IS NULL`, [ctx.users.user.id]).c;
    assert.ok(before >= 1);
    const res = await admin.patch(`/api/users/${ctx.users.user.id}`, { roles: ['USER'] });
    assert.equal(res.status, 200);
    const after = ctx.runtime.db.get(`SELECT count(*) AS c FROM sessions WHERE user_id = ? AND revoked_at IS NULL`, [ctx.users.user.id]).c;
    assert.equal(after, 0, 'la session de l’utilisateur dont les rôles ont changé est coupée');
    assert.equal((await user.get('/api/auth/me')).status, 401, 'et le cookie devient inerte');
  });

  it('refuse une permission inconnue dans une matrice de rôle', async () => {
    const roles = await admin.get('/api/roles');
    const userRole = roles.body.roles.find((r) => r.name === 'USER');
    const res = await admin.put(`/api/roles/${userRole.id}/permissions`, { permissions: ['users:create', 'tout-pouvoir'] });
    assert.equal(res.status, 400);
    assert.match(res.body.error.message, /inconnue/);
  });

  it('protège le rôle ADMIN contre une modification auto-blocante', async () => {
    const roles = await admin.get('/api/roles');
    const adminRole = roles.body.roles.find((r) => r.name === 'ADMIN');
    const res = await admin.put(`/api/roles/${adminRole.id}/permissions`, { permissions: ['dashboard:read'] });
    assert.equal(res.status, 400, 'retirer admin:access/roles:update à ADMIN est refusé');
    assert.match(res.body.error.details.blocked.join(','), /admin:access/);
  });

  it('applique une matrice valide et la rend effective immédiatement', async () => {
    const roles = await admin.get('/api/roles');
    const userRole = roles.body.roles.find((r) => r.name === 'USER');
    const res = await admin.put(`/api/roles/${userRole.id}/permissions`, {
      permissions: ['dashboard:read', 'files:create', 'documents:analyze', 'urls:analyze', 'agents:read', 'audit:read'],
    });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    await user.login(USER.id, USER.password);
    const audit = await user.get('/api/admin/audit?limit=1');
    assert.equal(audit.status, 200, 'la permission fraîchement accordée est appliquée sans redémarrage');
    // remise en état pour les tests suivants
    await admin.put(`/api/roles/${userRole.id}/permissions`, {
      permissions: ['dashboard:read', 'files:create', 'documents:analyze', 'urls:analyze', 'agents:read'],
    });
    ctx.runtime.rbac.invalidate();
    await user.login(USER.id, USER.password);
    assert.equal((await user.get('/api/admin/audit?limit=1')).status, 403, 'et le retrait est également immédiat');
  });

  it('crée un rôle personnalisé et le supprime', async () => {
    const created = await admin.post('/api/roles', { name: 'AUDITEUR', description: 'Lecture seule du journal' });
    assert.equal(created.status, 201, JSON.stringify(created.body));
    const id = created.body.role.id;
    const granted = await admin.put(`/api/roles/${id}/permissions`, { permissions: ['audit:read'] });
    assert.equal(granted.status, 200);
    const delSystem = await admin.del(`/api/roles/${ctx.runtime.rbac.roleByName('USER').id}`);
    assert.equal(delSystem.status, 400, 'rôle système non supprimable');
    const del = await admin.del(`/api/roles/${id}`);
    assert.equal(del.status, 200);
  });

  it('refuse la suppression d’un rôle porté par des utilisateurs', async () => {
    const roles = await admin.get('/api/roles');
    const userRole = roles.body.roles.find((r) => r.name === 'USER');
    const res = await admin.del(`/api/roles/${userRole.id}`);
    assert.ok([400, 409].includes(res.status), `suppression bloquée (${res.status})`);
  });

  it('accepte l’authentification par jeton Porteur pour les clients API', async () => {
    const c = ctx.client();
    const login = await c.login(ADMIN.id, ADMIN.password);
    assert.equal(login.status, 200);
    const token = c.jar.get('ps_session');
    const res = await fetch(`${ctx.base}/api/me`, { headers: { authorization: `Bearer ${token}` } });
    assert.equal(res.status, 200);
    // Sans cookie, les écritures restent possibles pour un client API, mais
    // uniquement avec le jeton : vérifier qu’un jeton invalide est refusé.
    const bad = await fetch(`${ctx.base}/api/me`, { headers: { authorization: 'Bearer ' + 'f'.repeat(64) } });
    assert.equal(bad.status, 401);
  });
});
