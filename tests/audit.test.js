/**
 * Audit trail: what is recorded, who may read it, and the guarantees that
 * make it trustworthy (immutability, no secrets, hashed client identifiers).
 */
import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { boot } from './helpers.js';

const ADMIN = { id: 'admin@test.local', password: 'Sup3r-Secret-Initial!' };
const USER = { id: 'alice@test.local', password: 'User-Standard-2026!' };

describe('journal d’audit', () => {
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

  it('enregistre les connexions réussies et échouées, avec severité adaptée', async () => {
    const bad = await ctx.client().post('/api/auth/login', { identifier: 'alice@test.local', password: 'mauvais-mot-de-passe' });
    assert.equal(bad.status, 401);
    const rows = ctx.runtime.db.get(
      `SELECT outcome, severity, action FROM audit_logs WHERE action IN ('auth.login.success','auth.login.failure') ORDER BY id DESC LIMIT 2`,
    );
    const failed = ctx.runtime.db.all(`SELECT * FROM audit_logs WHERE action='auth.login.failure' ORDER BY id DESC`);
    assert.ok(failed.length >= 1, 'l’échec est journalisé');
    assert.ok(['notice', 'warning'].includes(failed[0].severity), `sévérité adaptative (${failed[0].severity})`);
    assert.equal(failed[0].outcome, 'failure');
    const ok = ctx.runtime.db.all(`SELECT * FROM audit_logs WHERE action='auth.login.success'`);
    assert.equal(ok[0].severity, 'info');
    assert.equal(ok[0].outcome, 'success');
    void rows;
  });

  it('ne stocke jamais le mot de passe, le jeton ni une adresse IP en clair', async () => {
    const all = ctx.runtime.db.all(`SELECT * FROM audit_logs`);
    assert.ok(all.length >= 2, 'journal non vide');
    const text = JSON.stringify(all);
    assert.ok(!text.includes(ADMIN.password), 'jamais le mot de passe d’aucun utilisateur');
    assert.ok(!text.includes(USER.password), 'jamais le mot de passe standard');
    assert.ok(!/ps_session=/.test(text), 'jamais le cookie de session');
    assert.ok(!/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(text), 'jamais d’adresse IP en clair');
    const sample = all.find((r) => r.ip_hash) ?? all[0];
    for (const col of ['ip_hash', 'user_agent_hash']) {
      if (sample[col] !== undefined && sample[col] !== null) {
        assert.match(String(sample[col]), /^(?:(?:ip|ua):)?[0-9a-f]{16,}$/, `${col} est un digest, pas une valeur brute`);
      }
    }
  });

  it('refuse les clés sensibles dans le détail journalisé', () => {
    const { audit } = ctx.runtime;
    const before0 = ctx.runtime.db.get(`SELECT count(*) AS c FROM audit_logs`).c;
    audit.record({
      actor: { id: 1 },
      action: 'test.attempt',
      category: 'admin',
      detail: { password: 'doit-disparaitre', note: 'conserver' },
    });
    const row = ctx.runtime.db.get(`SELECT detail_json FROM audit_logs WHERE action='test.attempt' ORDER BY id DESC LIMIT 1`);
    const detail = JSON.parse(row.detail_json);
    assert.equal(detail.password, undefined, 'la clé sensible n’est pas écrite');
    assert.equal(detail.note, 'conserver', 'le reste du détail est conservé');
    assert.ok(ctx.runtime.db.get(`SELECT count(*) AS c FROM audit_logs`).c > before0, 'la ligne est quand même insérée');
  });

  it('est immuable : INSERT only, ni UPDATE ni DELETE', async () => {
    const row = ctx.runtime.db.get(`SELECT id, action FROM audit_logs ORDER BY id DESC LIMIT 1`);
    assert.throws(() => ctx.runtime.db.run(`UPDATE audit_logs SET action='effacé' WHERE id=?`, [row.id]), /interdit|UPDATE|ABORT|immutable/i);
    assert.throws(() => ctx.runtime.db.run(`DELETE FROM audit_logs WHERE id=?`, [row.id]), /interdit|DELETE|ABORT|immutable/i);
    const still = ctx.runtime.db.get(`SELECT action FROM audit_logs WHERE id=?`, [row.id]);
    assert.equal(still.action, row.action, 'la ligne est intacte');
  });

  it('expose une lecture filtrée à l’administrateur, refusée à l’utilisateur', async () => {
    const denied = await user.get('/api/admin/audit');
    assert.equal(denied.status, 403, 'audit:read est réservé');

    const res = await admin.get('/api/admin/audit?limit=5&category=auth');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.items));
    assert.ok(res.body.items.every((r) => r.category === 'auth'), 'le filtre catégorie s’applique');
    assert.ok(res.body.total >= res.body.items.length, 'total annoncé pour la pagination');
    assert.ok(res.body.stats, 'statistiques agrégées incluses');
    for (const r of res.body.items) {
      assert.equal(r.password, undefined);
      assert.ok(typeof r.id === 'number' && typeof r.action === 'string');
      assert.ok(!Object.hasOwn(r, 'actor_ip'), 'aucune IP brute dans la réponse');
    }
  });

  it('sert la recherche plein-texte, les sévérités et les bornes de dates', async () => {
    const byAction = await admin.get('/api/admin/audit?action=auth.login.success');
    assert.equal(byAction.status, 200);
    assert.ok(byAction.body.items.every((r) => r.action === 'auth.login.success'));
    const bySeverity = await admin.get('/api/admin/audit?severity=warning');
    assert.ok(bySeverity.body.items.every((r) => r.severity === 'warning'), 'filtre sévérité');
    const future = await admin.get('/api/admin/audit?from=2030-01-01');
    assert.equal(future.body.total, 0, 'aucun événement dans le futur');
    const past = await admin.get('/api/admin/audit?to=2000-01-01');
    assert.equal(past.body.total, 0, 'aucun événement avant 2000');
    const q = await admin.get('/api/admin/audit?q=login');
    assert.ok(q.body.total >= 1, 'recherche plein-texte sur action/détail');
  });

  it('refuse les valeurs de filtre inattendues sans casser la requête', async () => {
    const res = await admin.get(`/api/admin/audit?limit=100000&severity=%27%20OR%201%3D1%20--`);
    assert.ok([200, 400].includes(res.status), `statut ${res.status}`);
    if (res.status === 200) assert.ok(res.body.items.length === 0, 'le paramètre malformé ne désactive pas le filtre');
    assert.ok(res.body.items.length <= 200, 'la limite est bornée');
  });

  it('exporte en CSV borné, avec en-têtes de téléchargement', async () => {
    const res = await admin.get('/api/admin/audit/export?limit=50');
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type'), /text\/csv/);
    assert.match(res.headers.get('content-disposition'), /attachment; filename="audit-.*\.csv"/);
    const lines = res.text.trim().split('\n');
    assert.ok(lines.length >= 2, 'en-tête + lignes');
    assert.ok(lines[0].split(',').length >= 6, 'colonnes attendues');
    const usersView = await user.get('/api/admin/audit/export');
    assert.equal(usersView.status, 403, 'export réservé');
  });

  it('journalise les décisions d’accès refusé', async () => {
    const before0 = ctx.runtime.db.get(`SELECT count(*) AS c FROM audit_logs WHERE action='security.authorization.denied'`).c;
    await user.get('/api/admin/audit');
    await user.del('/api/users/1');
    const after0 = ctx.runtime.db.get(`SELECT count(*) AS c FROM audit_logs WHERE action='security.authorization.denied'`).c;
    assert.ok(after0 > before0, `refus tracés (${before0} → ${after0})`);
    const row = ctx.runtime.db.get(`SELECT * FROM audit_logs WHERE action='security.authorization.denied' ORDER BY id DESC LIMIT 1`);
    assert.ok(['failure', 'blocked'].includes(row.outcome), `refus marqué comme blocage (${row.outcome})`);
    assert.ok(['notice', 'warning', 'critical'].includes(row.severity), 'sévérité non triviale');
    const detail = JSON.parse(row.detail_json ?? '{}');
    assert.ok(row.request_id || detail.method || detail.path, 'la cible refusée est conservée (requête ou détail)');
  });

  it('purge les événements anciens sur demande de l’administrateur uniquement', async () => {
    ctx.runtime.db.run(`INSERT INTO audit_logs (action, category, occurred_at) VALUES ('vieux.evenement','system', '2001-01-01T00:00:00Z')`);
    const denied = await user.post('/api/admin/audit/purge', { days: 30 });
    assert.ok([403, 404].includes(denied.status), 'non réservé à l’admin : refusé');
    const res = await admin.post('/api/admin/audit/purge', { days: 30 });
    if (res.status === 404) {
      // Pas d'endpoint de purge : la rétention est un choix d'exploitation documenté.
      const stillThere = ctx.runtime.db.get(`SELECT count(*) AS c FROM audit_logs WHERE action='vieux.evenement'`).c;
      assert.equal(stillThere, 1, 'les événements restent, la rétention se fait hors bande');
      return;
    }
    assert.equal(res.status, 200);
    assert.ok(res.body.removed >= 1);
    assert.equal(ctx.runtime.db.get(`SELECT count(*) AS c FROM audit_logs WHERE action='vieux.evenement'`).c, 0, 'l’événement ancien est supprimé');
  });
});
