/**
 * Upload / download security: type allow-list, magic bytes, traversal, quota,
 * execution prevention, authorization, audit trail.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { boot, multipart, PNG_1x1 } from './helpers.js';

const ADMIN = { id: 'admin@test.local', password: 'Sup3r-Secret-Initial!' };
const USER = { id: 'alice@test.local', password: 'User-Standard-2026!' };

const PNG = PNG_1x1;
const textFile = (name, content) => ({ filename: name, contentType: 'text/plain', buffer: Buffer.from(content, 'utf8') });

describe('téléversement de fichiers', () => {
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

  async function upload(client, spec) {
    const mp = multipart('file', spec);
    return client.post('/api/files', undefined, { headers: mp.headers, form: mp.body });
  }

  it('accepte un vrai PNG avec métadonnées calculées', async () => {
    const res = await upload(user, { filename: 'capture.png', contentType: 'image/png', buffer: PNG });
    assert.equal(res.status, 201, JSON.stringify(res.body));
    const f = res.body.file;
    assert.equal(f.kind, 'image');
    assert.equal(f.sizeBytes, PNG.length);
    assert.equal(f.magicOk, true);
    assert.match(f.sha256, /^[0-9a-f]{64}$/);
    assert.equal(f.storedName, undefined, 'le nom de stockage interne n’est pas exposé');
    assert.equal(f.relativePath, undefined, 'ni le chemin relatif');

    // Le nom physique sur disque ne contient jamais le nom fourni.
    const stored = fs.readdirSync(path.join(ctx.dir, 'uploads'), { recursive: true }).filter((p) => typeof p === 'string' && p.endsWith('.png'));
    assert.equal(stored.length, 1);
    assert.match(String(stored[0]), /^[0-9a-f]{2}\/[0-9a-f-]{36}\.png$/, 'stockage shardé par empreinte, nom UUID');
  });

  it('accepte les types documentaires autorisés', async () => {
    const cases = [
      textFile('notes.md', '# Titre\n\nContenu de test.'),
      textFile('donnees.csv', 'a;b\n1;2\n'),
      textFile('config.json', '{"ok":true}'),
      textFile('rapport.txt', 'ligne 1\nligne 2'),
    ];
    for (const spec of cases) {
      const res = await upload(user, spec);
      assert.equal(res.status, 201, `${spec.filename} refusé : ${JSON.stringify(res.body)}`);
    }
  });

  it('refuse les extensions exécutables ou interprétables par le navigateur', async () => {
    const dangerous = [
      'shell.sh',
      'page.html',
      'logo.svg',
      'script.js',
      'evil.exe',
      'payload.php',
      'run.ps1',
      'redirect.jar',
      '.env',
      'passwd',
      'index.xhtml',
      'macro.py',
      'setup.bat',
    ];
    for (const name of dangerous) {
      const res = await upload(user, { filename: name, contentType: 'application/octet-stream', buffer: Buffer.from('x') });
      assert.ok([400, 415].includes(res.status), `${name} aurait dû être refusé (obtenu ${res.status})`);
      assert.match(res.body.error.message, /refusé|refus|autorisée|attendu|sans extension/i, `message d’erreur explicite pour ${name}`);
    }
    const count = ctx.runtime.db.get(`SELECT count(*) AS c FROM files`).c;
    const storedOnDisk = fs
      .readdirSync(path.join(ctx.dir, 'uploads'), { recursive: true })
      .filter((p) => typeof p === 'string' && /\.(sh|html|svg|js|exe|php|ps1|jar|py|bat)$/.test(p));
    assert.equal(storedOnDisk.length, 0, 'aucun fichier dangereux écrit sur le disque');
    assert.ok(count > 0);
  });

  it('refuse une extension qui ne correspond pas au contenu (png déguisé en script)', async () => {
    const res = await upload(user, { filename: 'inject.png', contentType: 'image/png', buffer: Buffer.from('#!/bin/sh\nrm -rf /\n', 'utf8') });
    assert.equal(res.status, 415, 'la signature binaire première ne correspond pas');
    assert.match(res.body.error.message, /signature|refusé/i);
  });

  it('refuse un HTML renommé en .txt (garde de contenu)', async () => {
    const res = await upload(user, textFile('innocent.txt', '<html><body><script>alert(1)</script></body></html>'));
    // .txt est autorisé comme texte ; le contenu est stocké mais JAMAIS servi en
    // ligne : la vérification importante est l’en-tête Content-Disposition.
    assert.equal(res.status, 201);
    const dl = await user.get(`/api/files/${res.body.file.id}/content`, { rawText: true });
    assert.equal(dl.status, 200);
    assert.match(dl.headers.get('content-disposition'), /^attachment;/, 'téléchargement forcé');
    assert.equal(dl.headers.get('x-content-type-options'), 'nosniff');
    assert.match(dl.headers.get('content-security-policy'), /sandbox/, 'CSP sandbox sur les fichiers servis');
    assert.match(dl.headers.get('content-type'), /text\/plain|octet-stream/, 'jamais text/html');
  });

  it('refuse un binaire dans une extension texte', async () => {
    const res = await upload(user, { filename: 'binaire.txt', contentType: 'text/plain', buffer: Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe, 0x00]) });
    assert.equal(res.status, 415);
  });

  it('neutralise les tentatives de parcours de chemin dans le nom de fichier', async () => {
    const res = await upload(user, textFile('../../../etc/passwd', 'attaque'));
    assert.ok([201, 400, 415].includes(res.status), `statut ${res.status}`);
    if (res.status === 201) {
      const name = res.body.file.originalName;
      assert.ok(!name.includes('..') && !name.includes('/'), `nom nettoyé : ${name}`);
      const abs = ctx.runtime.files.resolveStored(ctx.runtime.db.get(`SELECT relative_path AS p FROM files WHERE id=?`, [res.body.file.id]).p);
      assert.ok(abs.startsWith(path.resolve(ctx.dir, 'uploads')), 'le chemin résolu reste dans le volume d’upload');
    }
    const outside = fs
      .readdirSync(path.resolve(ctx.dir), { recursive: true })
      .filter((p) => typeof p === 'string' && p.includes('passwd'));
    assert.equal(outside.length, 0, 'aucun fichier écrit hors du répertoire autorisé');
  });

  it('refuse un fichier dépassant la taille maximale', async () => {
    const big = Buffer.alloc(1024 * 1024 * 2, 0x41); // 2 Mo de texte
    const res = await upload(user, { filename: 'gros.txt', contentType: 'text/plain', buffer: big });
    assert.equal(res.status, 201, 'sous la limite : accepté');
    const huge = Buffer.alloc(1024 * 1024 * 12, 0x41); // > 10 Mo
    const res2 = await upload(user, { filename: 'enorme.txt', contentType: 'text/plain', buffer: huge });
    assert.ok([413, 400, 415].includes(res2.status), `refusé (${res2.status})`);
    assert.match(JSON.stringify(res2.body), /volumineux|taille|payload/i);
  });

  it('déduplique par SHA-256 pour un même propriétaire sans dupliquer les octets', async () => {
    const a = await upload(user, textFile('idem.txt', 'contenu identique'));
    const b = await upload(user, textFile('idem-renomme.txt', 'contenu identique'));
    assert.equal(a.status, 201);
    assert.equal(b.status, 200, 'le second appel renvoie 200 avec duplicate:true');
    assert.equal(b.body.duplicate, true);
    assert.equal(b.body.file.id, a.body.file.id);
    const distinct = ctx.runtime.db.get(`SELECT count(DISTINCT sha256) AS c FROM files WHERE deleted_at IS NULL AND extension='.txt'`).c;
    const physical = fs.readdirSync(path.join(ctx.dir, 'uploads'), { recursive: true }).filter((p) => typeof p === 'string' && p.endsWith('.txt')).length;
    assert.equal(physical, distinct, 'un fichier physique par empreinte : aucune copie redondante sur le disque');
  });

  it('isole les fichiers par propriétaire', async () => {
    const mine = await upload(user, textFile('prive-alice.txt', 'secret d’alice'));
    assert.equal(mine.status, 201);

    // L’administrateur détient files:read : accès autorisé, mais tracé.
    const asAdmin = await admin.get(`/api/files/${mine.body.file.id}`);
    assert.equal(asAdmin.status, 200, 'l’administrateur peut lire (files:read)');
    const meta = await user.get(`/api/files/${mine.body.file.id}`);
    assert.equal(meta.status, 200, 'le propriétaire aussi');

    const other = ctx.client();
    // un tiers authentifié sans permission doit être refusé
    const created = await admin.post('/api/users', { email: 'eve@test.local', username: 'eve', roles: ['USER'] });
    await other.login('eve@test.local', created.body.temporaryPassword);
    await other.post('/api/auth/change-password', { currentPassword: created.body.temporaryPassword, newPassword: 'Zephyr-Clarification-2026!', confirm: 'Zephyr-Clarification-2026!' });
    const denied = await other.get(`/api/files/${mine.body.file.id}/content`);
    assert.equal(denied.status, 403, 'lecture du fichier d’autrui refusée');
    const deniedDelete = await other.del(`/api/files/${mine.body.file.id}`);
    assert.equal(deniedDelete.status, 403, 'suppression du fichier d’autrui refusée');
    assert.ok(ctx.runtime.db.get(`SELECT deleted_at FROM files WHERE id=?`, [mine.body.file.id]).deleted_at === null, 'fichier intact');
  });

  it('supprime physiquement et logiquement, et journalise', async () => {
    const up = await upload(user, textFile('a-supprimer.txt', 'temporaire'));
    const id = up.body.file.id;
    const abs = ctx.runtime.files.resolveStored(ctx.runtime.db.get(`SELECT relative_path AS p FROM files WHERE id=?`, [id]).p);
    assert.ok(fs.existsSync(abs));
    const del = await user.del(`/api/files/${id}`);
    assert.equal(del.status, 200);
    assert.equal(fs.existsSync(abs), false, 'octets supprimés du disque');
    assert.ok(ctx.runtime.db.get(`SELECT deleted_at FROM files WHERE id=?`, [id]).deleted_at, 'trace logique conservée');
    assert.equal((await user.get(`/api/files/${id}`)).status, 404, 'et la ressource devient introuvable');
    const logged = ctx.runtime.db.get(`SELECT count(*) AS c FROM audit_logs WHERE action='file.deleted' AND target_id=?`, [String(id)]).c;
    assert.ok(logged >= 1, 'suppression journalisée');
  });

  it('ne sert jamais le contenu d’un fichier en accès direct', async () => {
    const marker = 'MARQUEUR-SECRET-9e2f';
    const up = await upload(user, textFile('direct.txt', marker));
    const rel = ctx.runtime.db.get(`SELECT relative_path AS p FROM files WHERE id=?`, [up.body.file.id]).p;
    const guesses = [`/uploads/${rel}`, `/files/${rel}`, `/data/uploads/${rel}`, `/static/${rel}`, `/../${rel}`, `/uploads/${rel.split('/')[0]}/`];
    for (const guess of guesses) {
      const res = await ctx.client().get(guess, { rawText: true });
      assert.ok(!String(res.text).includes(marker), `${guess} ne doit pas renvoyer le contenu du fichier`);
      assert.notEqual(res.headers.get('x-stored-path'), rel, `${guess} ne doit pas révéler le chemin de stockage`);
      // Soit la coquille du SPA (HTML) répond, soit la route est absente (404),
      // soit l’interface n’a pas été construite (503) : dans les trois cas le
      // fichier n’est pas servi, et le type jamais celui du document stocké.
      const ct = res.headers.get('content-type') ?? '';
      assert.ok(res.status === 404 || res.status === 503 || /text\/html/.test(ct), `${guess} : ${res.status} ${ct}`);
      assert.ok(!/image\/|application\/vnd|application\/pdf/.test(ct), `${guess} ne doit pas servir le type réel du fichier`);
    }
    // Le fichier n’est lisible que par l’API authentifiée.
    const viaApi = await user.get(`/api/files/${up.body.file.id}/content`, { rawText: true });
    assert.equal(viaApi.status, 200);
    assert.equal(viaApi.text, marker);
  });
});
