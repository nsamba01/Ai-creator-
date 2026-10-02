/**
 * SSRF and outbound-request policy.
 *
 * The agent must never become a proxy to internal systems. Two levels are
 * verified: the pure policy functions, and the real HTTP behaviour of the
 * running server (including a live call that must be blocked).
 */
import assert from 'node:assert/strict';
import net from 'node:net';
import { after, before, describe, it } from 'node:test';
import { isBlockedAddress, assertSafeUrl, SsrfError, createSafeLookup, safeHref } from '../src/utils/net.js';
import { htmlDigest } from '../src/services/url.service.js';
import { boot } from './helpers.js';

const ADMIN = { id: 'admin@test.local', password: 'Sup3r-Secret-Initial!' };

describe('classification des adresses', () => {
  const blocked = [
    '127.0.0.1',
    '127.5.5.5',
    '0.0.0.0',
    '10.1.2.3',
    '172.16.0.1',
    '172.31.255.255',
    '192.168.1.1',
    '169.254.169.254',
    '100.64.0.1',
    '198.18.0.1',
    '224.0.0.1',
    '240.0.0.1',
    '::1',
    '::',
    'fe80::1',
    'fc00::1',
    'fd12:3456::7',
    'ff02::1',
    '::ffff:127.0.0.1',
    '::ffff:10.0.0.1',
    '2002:7f00:0001::',
    'not-an-ip',
    '',
    undefined,
  ];
  for (const ip of blocked) {
    it(`bloque ${JSON.stringify(ip)}`, () => {
      assert.equal(isBlockedAddress(ip), true);
    });
  }

  const allowed = ['8.8.8.8', '1.1.1.1', '93.184.216.34', '2606:4700:4700::1111', '172.15.0.1', '172.32.0.1', '100.63.0.1', '100.128.0.1'];
  for (const ip of allowed) {
    it(`autorise ${ip}`, () => {
      assert.equal(isBlockedAddress(ip), false);
    });
  }
});

describe('politique d’URL', () => {
  const opts = { allowedProtocols: new Set(['http:', 'https:']), allowedPorts: new Set([80, 443, 8080, 8443]), allowPrivate: false };

  it('refuse les protocoles non HTTP (file, gopher, dict, ftp)', () => {
    for (const u of ['file:///etc/passwd', 'gopher://127.0.0.1:11211/', 'dict://localhost/', 'ftp://example.com/x', 's3://bucket/key']) {
      assert.throws(() => assertSafeUrl(u, opts), (e) => e instanceof SsrfError && /protocole/.test(e.message), u);
    }
  });

  it('refuse les littéraux d’adresse privée', () => {
    for (const u of ['http://127.0.0.1/', 'http://169.254.169.254/latest/meta-data/', 'https://10.0.0.5/', 'http://[::1]/', 'http://192.168.0.1/admin']) {
      assert.throws(() => assertSafeUrl(u, opts), /refusé|interne|privée/, u);
    }
  });

  it('refuse les noms internes et les endpoints de métadonnées', () => {
    for (const u of [
      'http://localhost:3000/api',
      'http://metadata.google.internal/computeMetadata/v1/',
      'http://host.docker.internal:2375/',
      'http://db.internal:5432/',
      'http://printer.local/',
      'http://[fd00::1]/',
    ]) {
      assert.throws(() => assertSafeUrl(u, opts), /interne|privée|refusé/, u);
    }
  });

  it('refuse les identifiants dans l’URL et les ports non listés', () => {
    assert.throws(() => assertSafeUrl('https://admin:root@example.com/', opts), /identifiants/);
    assert.throws(() => assertSafeUrl('http://example.com:22/', opts), /port/);
    assert.throws(() => assertSafeUrl('http://example.com:6379', opts), /port/);
    assert.throws(() => assertSafeUrl('http://example.com' + '/x?y=' + 'a'.repeat(3000), opts), /longue/);
  });

  it('accepte une URL publique classique et un port autorisé', () => {
    const ok = assertSafeUrl('https://example.com/rapport?q=1', opts);
    assert.equal(ok.host, 'example.com');
    assert.equal(ok.port, 443);
    const alt = assertSafeUrl('http://example.org:8080/', opts);
    assert.equal(alt.port, 8080);
  });

  it('permet d’ouvrir explicitement le réseau interne (option risquée, journalisée)', () => {
    const open = assertSafeUrl('http://127.0.0.1:8080/healthz', { ...opts, allowPrivate: true });
    assert.equal(open.host, '127.0.0.1');
    assert.equal(open.port, 8080);
    // Sans cette option, la même cible est refusée.
    assert.throws(() => assertSafeUrl('http://127.0.0.1:8080/healthz', opts), /privée|interne/);
  });

  it('safeHref ne révèle ni identifiants ni requête', () => {
    assert.equal(safeHref('https://user:pass@example.com/secret?token=abc'), 'https://example.com/secret');
    assert.equal(safeHref('pas une url'), '(url invalide)');
  });
});

describe('lookup sécurisé (anti DNS rebinding)', () => {
  it('refuse un nom qui résout vers 127.0.0.1', async () => {
    const lookup = createSafeLookup({ allowPrivate: false });
    const err = await new Promise((resolve) => {
      // 'localhost' résout vers 127.0.0.1/::1 dans le conteneur de test.
      lookup('localhost', { all: true }, (e) => resolve(e));
    });
    assert.ok(err instanceof SsrfError, `erreur attendue, obtenu ${err}`);
    assert.match(err.message, /adresse interne/);
  });

  it('accepte une adresse publique littérale', async () => {
    const lookup = createSafeLookup({ allowPrivate: false });
    const out = await new Promise((resolve, reject) => lookup('example.com', { all: true }, (e, r) => (e ? reject(e) : resolve(r))));
    assert.ok(Array.isArray(out) && out.length >= 1);
    for (const rec of out) assert.equal(net.isIP(rec.address) > 0, true);
  });
});

describe('analyse d’URL par le serveur', () => {
  let ctx;
  let admin;
  before(async () => {
    ctx = await boot();
    admin = ctx.client();
    await admin.login(ADMIN.id, ADMIN.password);
  });
  after(async () => {
    await ctx.close();
  });

  it('valide la forme de l’URL avant tout appel réseau', async () => {
    const res = await admin.post('/api/urls/analyze', { url: 'javascript:alert(1)' });
    assert.equal(res.status, 400);
  });

  it('refuse la cible de métadonnées cloud 169.254.169.254', async () => {
    const res = await admin.post('/api/urls/analyze', { url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' });
    assert.equal(res.status, 400);
    assert.equal(res.body.error.code, 'SSRF_BLOCKED');
    const blocked = ctx.runtime.db.get(`SELECT count(*) AS c FROM url_analyses WHERE status='blocked'`).c;
    assert.ok(blocked >= 1, 'la tentative est journalisée');
    const audit = ctx.runtime.db.get(`SELECT count(*) AS c FROM audit_logs WHERE action='url.blocked'`).c;
    assert.ok(audit >= 1, 'et apparaît dans le journal de sécurité');
  });

  it('refuse sa propre adresse de bouclage (le serveur ne devient pas un proxy)', async () => {
    const res = await admin.post('/api/urls/analyze', { url: `${ctx.base}/healthz` });
    assert.equal(res.status, 400, 'interdit par la politique SSRF');
    assert.match(res.body.error.message, /interne|privée|refusé/i);
  });

  it('refuse les ports non autorisés et le préfixe localhost', async () => {
    for (const url of ['http://localhost:6379/', 'http://127.0.0.1:22/', 'https://example.com:3306/']) {
      const res = await admin.post('/api/urls/analyze', { url });
      assert.equal(res.status, 400, url);
    }
  });

  it('autorise explicitement le bouclage lorsque l’opérateur le demande', async (t) => {
    let open;
    try {
      open = await boot({ port: 43111, extraConfig: { URL_ALLOW_PRIVATE_HOSTS: '1', URL_ALLOWED_PORTS: '43111' } });
    } catch (err) {
      t.skip(`port de test indisponible : ${err.message}`);
      return;
    }
    const port = 43111;
    try {
      const c = open.client();
      await c.login(ADMIN.id, ADMIN.password);
      const res = await c.post('/api/urls/analyze', { url: `http://127.0.0.1:${port}/healthz` });
      assert.equal(res.status, 200, JSON.stringify(res.body));
      assert.equal(res.body.httpStatus, 200);
      assert.match(res.body.contentType, /json/);
      const logged = open.runtime.db.get(`SELECT status FROM url_analyses ORDER BY id DESC LIMIT 1`).status;
      assert.equal(logged, 'ok');
    } finally {
      await open.close();
    }
  });

  it('expose les statistiques et la politique appliquée', async () => {
    const res = await admin.get('/api/urls/stats');
    assert.equal(res.status, 200);
    assert.ok(res.body.policy.allowPrivate === false);
    assert.ok(res.body.total >= 4, 'les tentatives sont comptées');
    assert.ok(res.body.blocked >= 4);
  });

  it('extrait un digest HTML utile (titre, méta, titres, formulaires)', () => {
    const html = `<!doctype html><html><head><title> Rapport de synthèse </title>
      <meta name="description" content="Résumé public du document">
      </head><body>
      <h1>Introduction</h1><h2>Méthode</h2>
      <p>Contenu &amp; détails.</p>
      <a href="/interne">interne</a> <a href="https://ext.example/x">externe</a> <a href="javascript:alert(1)">piège</a>
      <form action="/login" method="post"><input name="user"><input name="pass"></form>
      </body></html>`;
    const d = htmlDigest(html);
    assert.equal(d.title, 'Rapport de synthèse');
    assert.equal(d.meta.description, 'Résumé public du document');
    assert.deepEqual(d.headings.map((h) => h.text), ['Introduction', 'Méthode']);
    assert.equal(d.links, 3);
    assert.ok(d.externalLinks.some((l) => l.kind === 'dangerous-scheme'), 'le lien javascript: est marqué dangereux');
    assert.equal(d.forms[0].hasCsrfField, false, 'absence de champ anti-CSRF détectée');
    assert.doesNotThrow(() => htmlDigest('<script>while(1){}</script>'.repeat(500)));
  });

  it('refuse une URL trop longue ou vide', async () => {
    const empty = await admin.post('/api/urls/analyze', { url: '' });
    assert.equal(empty.status, 400);
    const long = await admin.post('/api/urls/analyze', { url: 'https://example.com/' + 'a'.repeat(2500) });
    assert.equal(long.status, 400, 'la limite de longueur est appliquée avant parsing');
  });
});
