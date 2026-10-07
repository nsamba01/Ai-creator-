/**
 * Phase B de l'agent vidéo : lecture en continu bornée + file d'exécution sous bail.
 *
 * Deux natures de preuves :
 *  - le découpage `Range` est vérifié **octet par octet** contre ce que `fs` relit du fichier,
 *    pas contre un nombre que j'aurais annoncé ;
 *  - la file est vérifiée sur ses trois promesses : un seul preneur, un bail qui expire et se
 *    ramasse, une rechute qui se retry puis s'arrête proprement — sans jamais laisser un chemin
 *    de stockage remonter jusqu'au client.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { boot, buildAvi, buildMp4, buildWebm, multipart } from './helpers.js';
import { createVideoJobRunner } from '../src/services/video-jobs.service.js';
import { parseByteRange, safeDispositionName } from '../src/services/video-stream.js';

const ADMIN = { id: 'admin@test.local', password: 'Sup3r-Secret-Initial!' };
const USER = { id: 'alice@test.local', password: null }; // complété par ctx.standardPassword

async function uploadVideo(client, { name, buffer, mime = 'video/mp4' }) {
  const mp = multipart('file', { filename: name, contentType: mime, buffer });
  return client.post('/api/files', undefined, { headers: mp.headers, form: mp.body });
}

describe('lecture en continu et file d’exécution (phase B)', () => {
  let ctx;
  let admin;
  let user;
  let userId;
  let file;
  let asset;
  let absPath;

  before(async () => {
    ctx = await boot();
    admin = ctx.client();
    user = ctx.client();
    await admin.login(ADMIN.id, ADMIN.password);
    await user.login(USER.id, ctx.standardPassword);
    userId = (await user.get('/api/auth/me')).body.user.id;
    await admin.put('/api/admin/settings', { entries: { 'video.enabled': true, 'video.async_probe': false } });
    const up = await uploadVideo(user, { name: 'plage.mp4', buffer: buildMp4({ durationMs: 3000, mdatSize: 8192 }) });
    assert.equal(up.status, 201, JSON.stringify(up.body));
    file = up.body.file;
    const declared = await user.post('/api/videos', { fileId: file.id });
    assert.equal(declared.status, 201, JSON.stringify(declared.body));
    asset = declared.body.asset;
    absPath = path.join(ctx.dir, 'uploads', file.relativePath ?? '');
    // Le chemin réel est lu depuis la base, pas deviné : les assertions d’octets s’appuient dessus.
    const row = ctx.runtime.db.get(`SELECT relative_path FROM files WHERE id = ?`, [file.id]);
    absPath = path.resolve(ctx.dir, 'uploads', row.relative_path);
  });

  after(async () => {
    await ctx.close();
  });

  async function rawFetch(client, urlPath, headers = {}, method = 'GET') {
    const h = { ...headers };
    const cookie = client.cookies();
    if (cookie) h.cookie = cookie;
    const res = await fetch(ctx.base + urlPath, { method, headers: h, redirect: 'manual' });
    const buf = Buffer.from(await res.arrayBuffer());
    return { status: res.status, headers: res.headers, bytes: buf, text: buf.toString('utf8') };
  }

  describe('découpage des plages (unitaire)', () => {
    it('accepte une plage, une queue de fichier, et refuse ce qui n’a pas de sens', () => {
      assert.deepEqual(parseByteRange(null, 1000), { mode: 'full' });
      assert.deepEqual(parseByteRange('bytes=0-499', 1000), { mode: 'range', start: 0, end: 499 });
      assert.deepEqual(parseByteRange('bytes=500-', 1000), { mode: 'range', start: 500, end: 999 });
      assert.deepEqual(parseByteRange('bytes=-200', 1000), { mode: 'range', start: 800, end: 999 });
      assert.deepEqual(parseByteRange('bytes=-0', 1000), { mode: 'unsatisfiable' }, 'une queue de zéro octet n’est pas une plage');
      assert.deepEqual(parseByteRange('bytes=1000-', 1000), { mode: 'unsatisfiable' }, 'début hors fichier');
      assert.deepEqual(parseByteRange('bytes=10-5', 1000), { mode: 'unsatisfiable' }, 'fin avant le début');
      assert.equal(parseByteRange('bytes=0-99999', 1000).end, 999, 'la fin est bornée à la taille réelle');
      assert.deepEqual(parseByteRange('bytes=0-1,4-5', 1000), { mode: 'full' }, 'plages multiples : ignorées, réponse complète');
      assert.deepEqual(parseByteRange('chiffres=abc', 1000), { mode: 'full' });
      assert.deepEqual(parseByteRange('bytes=abc-def', 1000), { mode: 'full' });
    });

    it('assainit un nom de fichier destiné à Content-Disposition', () => {
      assert.equal(safeDispositionName('vidéo (final) [2].mp4'), 'vidéo -final- -2-.mp4', 'parenthèses et crochets deviennent de la poncturation inoffensive');
      assert.doesNotThrow(() => Buffer.from(`inline; filename="${safeDispositionName('a\r\nSet-Cookie: x=1')}"`));
      assert.ok(!safeDispositionName('a\r\nSet-Cookie: x=1').includes('\r'));
      assert.ok(!safeDispositionName('a"x').includes('"'));
      assert.ok(!/\\/.test(safeDispositionName('C:\\windows\\x.mp4')));
      assert.equal(safeDispositionName(''), 'video');
      assert.ok(safeDispositionName('x'.repeat(500)).length <= 120);
    });
  });

  describe('route de lecture', () => {
    it('refuse de servir tant que video.stream_enabled est faux, et sans session', async () => {
      const off = await user.get(`/api/videos/${asset.id}/stream`);
      assert.equal(off.status, 409, JSON.stringify(off.body));
      assert.equal(off.body.error.code, 'VIDEO_STREAM_DISABLED');
      assert.match(off.body.error.message, /video\.stream_enabled/, 'la réponse dit comment ouvrir la capacité');

      const anon = await fetch(`${ctx.base}/api/videos/${asset.id}/stream`);
      assert.equal(anon.status, 401, 'aucun octet sans identité');
    });

    it('sert le fichier entier avec les en-têtes de négociation', async () => {
      await admin.put('/api/admin/settings', { key: 'video.stream_enabled', value: true });
      const res = await rawFetch(user, `/api/videos/${asset.id}/stream`);
      const real = fs.readFileSync(absPath);
      assert.equal(res.status, 200);
      assert.equal(res.bytes.length, real.length, 'la longueur annoncée est la longueur servie');
      assert.equal(res.headers.get('content-type'), 'video/mp4', 'type déduit du conteneur sondé');
      assert.equal(res.headers.get('accept-ranges'), 'bytes');
      assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
      assert.equal(res.headers.get('cross-origin-resource-policy'), 'same-origin');
      assert.match(res.headers.get('content-security-policy') ?? '', /default-src 'none'/);
      assert.match(res.headers.get('content-disposition'), /^inline; filename="plage\.mp4"$/);
      assert.match(res.headers.get('etag'), /^W\/"[0-9a-f]{16}-\d+"$/);
      assert.equal(res.headers.get('vary'), 'Cookie, Range');
    });

    it('respecte une plage demandée, octet par octet', async () => {
      const real = fs.readFileSync(absPath);
      const mid = await rawFetch(user, `/api/videos/${asset.id}/stream`, { range: 'bytes=100-599' });
      assert.equal(mid.status, 206);
      assert.equal(mid.headers.get('content-range'), `bytes 100-599/${real.length}`);
      assert.equal(mid.bytes.length, 500);
      assert.ok(mid.bytes.equals(real.subarray(100, 600)), 'les octets servis sont exactement la tranche demandée');

      const tail = await rawFetch(user, `/api/videos/${asset.id}/stream`, { range: 'bytes=-512' });
      assert.equal(tail.status, 206);
      assert.ok(tail.bytes.equals(real.subarray(real.length - 512)), 'la queue de fichier est lue depuis la fin réelle');

      const open = await rawFetch(user, `/api/videos/${asset.id}/stream`, { range: `bytes=${real.length - 8}-` });
      assert.equal(open.bytes.length, 8, 'une plage ouverte va jusqu’au bout, pas au-delà');
    });

    it('répond 416 sur une plage impossible, sans divulguer le stockage', async () => {
      const real = fs.readFileSync(absPath);
      const bad = await rawFetch(user, `/api/videos/${asset.id}/stream`, { range: `bytes=${real.length + 10}-` });
      assert.equal(bad.status, 416);
      assert.equal(bad.headers.get('content-range'), `bytes */${real.length}`);
      assert.equal(bad.bytes.length, 0, 'un 416 ne transporte pas de corps');
      assert.ok(!/\/(home|app|var|tmp|srv|data)\//.test(bad.text), `aucun chemin serveur dans la réponse : ${bad.text.slice(0, 120)}`);
    });

    it('négocie la revalidation et répond aux en-têtes sans corps', async () => {
      const first = await rawFetch(user, `/api/videos/${asset.id}/stream`);
      const etag = first.headers.get('etag');
      assert.ok(etag);
      const cached = await rawFetch(user, `/api/videos/${asset.id}/stream`, { 'if-none-match': etag });
      assert.equal(cached.status, 304);
      assert.equal(cached.bytes.length, 0);

      const head = await rawFetch(user, `/api/videos/${asset.id}/stream`, { range: 'bytes=0-9' }, 'HEAD');
      assert.equal(head.status, 206, 'HEAD honore Range côté en-têtes');
      assert.equal(head.headers.get('content-length'), '10');
      assert.equal(head.bytes.length, 0, 'HEAD ne renvoie aucun octet');
    });

    it('refuse une vidéo non prête, et n’écoute pas l’interface pour la portée', async () => {
      const quarantined = await admin.post(`/api/videos/${asset.id}/quarantine`, { reason: 'test de portée' });
      assert.equal(quarantined.status, 200);
      const denied = await rawFetch(user, `/api/videos/${asset.id}/stream`);
      assert.equal(denied.status, 409, 'une vidéo en quarantaine ne se lit pas');
      assert.equal(denied.body?.error?.code ?? JSON.parse(denied.text).error.code, 'VIDEO_NOT_READY');
      await admin.post(`/api/videos/${asset.id}/release`, {});

      const other = await uploadVideo(admin, { name: 'voisin.webm', buffer: buildWebm({}), mime: 'video/webm' });
      assert.equal(other.status, 201, JSON.stringify(other.body));
      const otherAsset = await admin.post('/api/videos', { fileId: other.body.file.id });
      assert.equal(otherAsset.status, 201, JSON.stringify(otherAsset.body));
      const stolen = await rawFetch(user, `/api/videos/${otherAsset.body.asset.id}/stream`);
      assert.equal(stolen.status, 403, 'le propriétaire d’une autre vidéo ne la lit pas');
      const borrowed = await rawFetch(admin, `/api/videos/${otherAsset.body.asset.id}/stream`);
      assert.equal(borrowed.status, 200, 'videos:read:any ouvre la portée, côté serveur');
    });

    it('refuse un fichier dont la taille sur disque a changé après déclaration', async () => {
      const st = fs.statSync(absPath);
      fs.appendFileSync(absPath, Buffer.from('0123456789abcdef'));
      try {
        const res = await rawFetch(user, `/api/videos/${asset.id}/stream`);
        assert.equal(res.status, 409);
        assert.equal(JSON.parse(res.text).error.code, 'VIDEO_SIZE_MISMATCH');
        const detail = JSON.parse(res.text).error.details;
        assert.deepEqual({ expected: detail.expected, found: detail.found }, { expected: st.size, found: st.size + 16 });
      } finally {
        // on remet le fichier dans son état précédent, et la base avec
        const fd = fs.openSync(absPath, 'r+');
        fs.truncateSync(fd, st.size);
        fs.closeSync(fd);
        ctx.runtime.db.run(`UPDATE files SET size_bytes = ? WHERE id = ?`, [st.size, file.id]);
      }
      const back = await rawFetch(user, `/api/videos/${asset.id}/stream`);
      assert.equal(back.status, 200, 'la lecture reprend dès que la taille concorde');
      assert.equal(back.bytes.length, st.size);
    });

    it('utilise le type conteneur pour les autres formats, et ne sert pas une source non validée', async () => {
      const avi = await uploadVideo(user, { name: 'ancien.avi', buffer: buildAvi({}), mime: 'video/x-msvideo' });
      assert.equal(avi.status, 201, JSON.stringify(avi.body));
      const declared = await user.post('/api/videos', { fileId: avi.body.file.id });
      assert.equal(declared.status, 201, JSON.stringify(declared.body));
      assert.equal(declared.body.asset.container, 'avi');
      const res = await rawFetch(user, `/api/videos/${declared.body.asset.id}/stream`);
      assert.equal(res.status, 200);
      assert.equal(res.headers.get('content-type'), 'video/x-msvideo', 'AVI n’est pas annoncé mp4');

      // La précédence est prouvée du bon côté : c’est le conteneur retenu par l’analyse qui commande,
      // pas le type déclaré à l’envoi (qui, lui, reste « video/x-msvideo » dans files).
      ctx.runtime.db.run(`UPDATE video_assets SET container = 'webm' WHERE id = ?`, [declared.body.asset.id]);
      const flipped = await rawFetch(user, `/api/videos/${declared.body.asset.id}/stream`);
      assert.equal(flipped.headers.get('content-type'), 'video/webm', 'le type servi suit l’analyse');
      ctx.runtime.db.run(`UPDATE video_assets SET container = 'avi' WHERE id = ?`, [declared.body.asset.id]);

      // Fichier dont la signature n’a pas été validée : la route doit le refuser.
      ctx.runtime.db.run(`UPDATE files SET magic_ok = 0 WHERE id = ?`, [file.id]);
      const unsafe = await rawFetch(user, `/api/videos/${asset.id}/stream`);
      assert.equal(unsafe.status, 403);
      assert.equal(JSON.parse(unsafe.text).error.code, 'VIDEO_UNSAFE_SOURCE');
      ctx.runtime.db.run(`UPDATE files SET magic_ok = 1 WHERE id = ?`, [file.id]);
      const back = await rawFetch(user, `/api/videos/${asset.id}/stream`);
      assert.equal(back.status, 200);
    });
  });

  /** Vider la file des tâches en attente laissées par les tests précédents (isolement, pas triche). */
  function drainQueued() {
    for (const row of ctx.runtime.db.all(`SELECT id FROM video_jobs WHERE status = 'queued'`)) {
      ctx.runtime.videoJobs.repo.cancel({ id: row.id });
    }
  }

  describe('file d’exécution', () => {
    it('accepte la mise en file et expose la liste sur /jobs (sans se faire dévorer par /:id)', async () => {
      const queued = await user.post(`/api/videos/${asset.id}/jobs`, { kind: 'probe' });
      assert.equal(queued.status, 202, JSON.stringify(queued.body));
      assert.equal(queued.body.job.kind, 'probe');
      assert.equal(queued.body.job.status, 'queued');

      const list = await user.get('/api/videos/jobs');
      assert.equal(list.status, 200, 'la route littérale /jobs prime sur /:id');
      assert.ok(list.body.items.some((j) => j.id === queued.body.job.id));
      assert.equal(list.body.scope, 'own');

      const stats = await user.get('/api/videos/jobs/stats');
      assert.ok(stats.body.queued >= 1);
      assert.equal(typeof stats.body.expiredLeases, 'number');
    });

    it('reste idempotente par couple (vidéo, kind)', async () => {
      const second = await user.post(`/api/videos/${asset.id}/jobs`, { kind: 'probe' });
      assert.equal(second.body.job.id, (await user.get('/api/videos/jobs')).body.items.find((j) => j.videoId === asset.id && j.kind === 'probe').id);
      const rows = ctx.runtime.db.get(`SELECT count(*) AS c FROM video_jobs WHERE video_id = ? AND kind = 'probe'`, [asset.id]).c;
      assert.equal(rows, 1, 'rejouer une analyse ne superpose pas les lignes');
    });

    it('réserve les kinds lourds à videos:process', async () => {
      const denied = await user.post(`/api/videos/${asset.id}/jobs`, { kind: 'thumbnail' });
      assert.equal(denied.status, 403);
      assert.match(denied.body.error.message, /videos:process/);
      const allowed = await admin.post(`/api/videos/${asset.id}/jobs`, { kind: 'thumbnail' });
      assert.equal(allowed.status, 202);
      const bad = await user.post(`/api/videos/${asset.id}/jobs`, { kind: 'pas-un-kind' });
      assert.equal(bad.status, 400, 'la liste des kinds est fermée');
    });

    it('ne donne qu’un seul preneur par tâche', async () => {
      const repo = ctx.runtime.videoJobs.repo;
      drainQueued();
      const queued = await user.post(`/api/videos/${asset.id}/jobs`, { kind: 'probe' });
      assert.equal(queued.status, 202);
      const a = repo.claim({ worker: 'walter', leaseMs: 60_000, kinds: ['probe'] });
      const b = repo.claim({ worker: 'gustave', leaseMs: 60_000, kinds: ['probe'] });
      assert.ok(a, 'le premier worker obtient la tâche');
      assert.equal(b, null, 'le second ne peut pas prendre la même');
      assert.equal(a.id, queued.body.job.id);
      const out = repo.finish({ id: a.id, worker: 'walter', ok: true, result: { done: true } });
      assert.equal(out.row.status, 'succeeded');
      assert.equal(out.row.progress, 100);
      assert.equal(ctx.runtime.db.get(`SELECT result_json FROM video_jobs WHERE id = ?`, [a.id]).result_json, '{"done":true}');
    });

    it('laisse un worker étranger à un kind tranquille', async () => {
      const repo = ctx.runtime.videoJobs.repo;
      drainQueued();
      const job = await admin.post(`/api/videos/${asset.id}/jobs`, { kind: 'thumbnail' });
      assert.equal(job.status, 202);
      assert.equal(repo.claim({ worker: 'sondeur', leaseMs: 60_000, kinds: ['probe'] }), null, 'un worker probe ne saisit pas une vignette');
      const taken = repo.claim({ worker: 'illustrateur', leaseMs: 60_000, kinds: ['thumbnail'] });
      assert.equal(taken.id, job.body.job.id, 'le worker concerné, lui, la trouve');
      repo.finish({ id: taken.id, worker: 'illustrateur', ok: true, result: {} });
    });

    it('libère une tâche dont le bail a expiré, et interdit à l’ancien worker de l’achever', async () => {
      const repo = ctx.runtime.videoJobs.repo;
      drainQueued();
      await user.post(`/api/videos/${asset.id}/jobs`, { kind: 'probe' });
      const claimed = repo.claim({ worker: 'mort', leaseMs: 1000, kinds: ['probe'] });
      assert.ok(claimed);
      ctx.runtime.db.run(`UPDATE video_jobs SET lease_expires_at = ? WHERE id = ?`, ['2000-01-01T00:00:00.000Z', claimed.id]);
      const reaped = repo.reapExpired({});
      assert.equal(reaped.requeued, 1, 'la tâche revient en file au lieu de bloquer la file');
      const afterReap = repo.getById(claimed.id);
      assert.equal(afterReap.status, 'queued');
      assert.equal(afterReap.attempts, 1, 'la tentative déjà comptée n’est pas effacée : c’est ce qui borne les rechutes');
      const late = repo.finish({ id: claimed.id, worker: 'mort', ok: true, result: { victoire: 'tardive' } });
      assert.equal(late.lost, true, 'un worker qui revient après son bail ne peut plus écrire');
      assert.equal(ctx.runtime.db.get(`SELECT result_json FROM video_jobs WHERE id = ?`, [claimed.id]).result_json, null);
    });

    it('borne les rechutes, retarde la relance, puis journalise un échec sans chemin', async () => {
      const repo = ctx.runtime.videoJobs.repo;
      drainQueued();
      await admin.put('/api/admin/settings', { entries: { 'video.max_attempts': 2, 'video.backoff_seconds': 3600 } });
      try {
        const job = await user.post(`/api/videos/${asset.id}/jobs`, { kind: 'probe' });
        assert.equal(job.status, 202, JSON.stringify(job.body));
        const runner = createVideoJobRunner({
          service: ctx.runtime.videoJobs,
          videos: ctx.runtime.videos,
          db: ctx.runtime.db,
          workerId: 'bourreau',
          kinds: ['probe'],
          handlers: {
            // Le message brute un chemin absolu : la base ne doit jamais le conserver tel quel.
            probe: async () => {
              throw new Error(`lecture impossible de ${absPath} : EIO`);
            },
          },
        });
        const first = await runner.tick();
        assert.equal(first.claimed[0].ok, false, JSON.stringify(first.claimed));
        const afterFirst = repo.getById(job.body.job.id);
        assert.equal(afterFirst.status, 'queued', 'une tâche non épuisée repasse en file');
        assert.ok(String(afterFirst.run_after) > new Date().toISOString(), `le backoff repousse l’échéance (${afterFirst.run_after})`);
        assert.equal(repo.nextClaimable({ kinds: ['probe'] }), null, 'pendant le délai, rien n’est réclamable');

        // On fait passer le temps (décret d’attente échu) plutôt que de tricher avec les réglages.
        ctx.runtime.db.run(`UPDATE video_jobs SET run_after = ? WHERE id = ?`, ['2000-01-01T00:00:00.000Z', job.body.job.id]);
        const second = await runner.tick();
        assert.equal(second.claimed.length, 1, 'délai échu, la tâche est de nouveau réclamable');
        const afterSecond = repo.getById(job.body.job.id);
        assert.equal(afterSecond.attempts, 2);
        assert.equal(afterSecond.status, 'failed', 'tentatives épuisées : la file ne s’emballe pas');
        assert.ok(!/\/(home|tmp|var|Users)\//.test(String(afterSecond.error_message)), `le message stocké ne divulgue pas le chemin : ${afterSecond.error_message}`);
        assert.match(String(afterSecond.error_message), /chemin masqué/);
      } finally {
        await admin.put('/api/admin/settings', { entries: { 'video.max_attempts': 3, 'video.backoff_seconds': 0 } });
      }
    });

    it('fait avancer une vidéo mise en file par le mode asynchrone, sans sondage dans la requête', async () => {
      drainQueued();
      await admin.put('/api/admin/settings', { entries: { 'video.async_probe': true } });
      try {
        const up = await uploadVideo(user, { name: 'differe.webm', buffer: buildWebm({ durationMs: 2100 }), mime: 'video/webm' });
        assert.equal(up.status, 201, JSON.stringify(up.body));
        const declared = await user.post('/api/videos', { fileId: up.body.file.id });
        assert.equal(declared.status, 201, JSON.stringify(declared.body));
        assert.equal(declared.body.queued, true, 'la requête a mis en file au lieu de sonder');
        assert.equal(declared.body.asset.status, 'pending', 'et n’a donc rien mesuré elle-même');
        assert.ok(declared.body.job.id);

        const runner = createVideoJobRunner({
          service: ctx.runtime.videoJobs,
          videos: ctx.runtime.videos,
          db: ctx.runtime.db,
          workerId: 'sondeur',
          kinds: ['probe'],
          handlers: {
            probe: async (job) => ctx.runtime.videos.probeForJob({ videoId: job.video_id }),
          },
        });
        const out = await runner.tick();
        assert.equal(out.claimed.length, 1, JSON.stringify(out));
        assert.equal(out.claimed[0].ok, true, JSON.stringify(out.claimed[0]));
        const done = await user.get(`/api/videos/${declared.body.asset.id}`);
        assert.equal(done.body.asset.status, 'ready', JSON.stringify(done.body.asset));
        assert.equal(done.body.asset.durationMs, 2100, 'le rapport vient du conteneur WebM réellement lu');
        assert.equal(done.body.asset.probeSource, 'header');

        // Le flux refuse tant que le rapport n’est pas prêt : la file ne sert pas de porte dérobée.
        await admin.put('/api/admin/settings', { entries: { 'video.async_probe': true, 'video.stream_enabled': true } });
        const pendingUp = await uploadVideo(user, { name: 'jamais-sonde.mp4', buffer: buildMp4({ durationMs: 1000, mdatSize: 512 }) });
        const pendingAsset = await user.post('/api/videos', { fileId: pendingUp.body.file.id });
        assert.equal(pendingAsset.body.asset.status, 'pending');
        const refused = await rawFetch(user, `/api/videos/${pendingAsset.body.asset.id}/stream`);
        assert.equal(refused.status, 409);
        assert.equal(JSON.parse(refused.text).error.code, 'VIDEO_NOT_READY', 'une vidéo non sondée n’est pas diffusée');
        assert.equal(pendingUp.status, 201);
      } finally {
        await admin.put('/api/admin/settings', { key: 'video.async_probe', value: false });
      }
    });

    it('signale nommément un kind sans exécuteur, au lieu de le faire réussir silencieusement', async () => {
      drainQueued();
      const job = await admin.post(`/api/videos/${asset.id}/jobs`, { kind: 'transcode' });
      assert.equal(job.status, 202);
      const runner = createVideoJobRunner({
        service: ctx.runtime.videoJobs,
        videos: ctx.runtime.videos,
        db: ctx.runtime.db,
        workerId: 'vide',
        handlers: {},
        kinds: ['transcode'],
      });
      const out = await runner.tick();
      assert.equal(out.claimed.length, 1, JSON.stringify(out));
      assert.equal(out.claimed[0].errorCode, 'VIDEO_TOOL_UNAVAILABLE', JSON.stringify(out.claimed[0]));
      const row = ctx.runtime.db.get(`SELECT status, error_code, run_after FROM video_jobs WHERE id = ?`, [job.body.job.id]);
      assert.equal(row.error_code, 'VIDEO_TOOL_UNAVAILABLE');
      assert.ok(String(row.run_after) > new Date().toISOString(), 'la relance est repoussée : pas de boucle serrée sur une tâche qu’on ne sait pas faire');
    });

    it('permet à l’administration de ramasser les bails et d’annuler, pas au compte standard', async () => {
      const denied = await user.post('/api/videos/jobs/reap', {});
      assert.equal(denied.status, 403, 'videos:manage-jobs commande le ramassage');
      const job = await user.post(`/api/videos/${asset.id}/jobs`, { kind: 'probe' });
      const cancelled = await user.post(`/api/videos/jobs/${job.body.job.id}/cancel`, {});
      assert.equal(cancelled.status, 200);
      assert.equal(cancelled.body.job.status, 'cancelled');
      const requeued = await user.post(`/api/videos/jobs/${job.body.job.id}/retry`, {});
      assert.equal(requeued.status, 200);
      assert.equal(requeued.body.job.status, 'queued');
      assert.equal(requeued.body.job.attempts, 0, 'une relance repart avec ses chances');
      const reaped = await admin.post('/api/videos/jobs/reap', {});
      assert.equal(reaped.status, 200);
      assert.equal(typeof reaped.body.examined, 'number');
      assert.equal(reaped.body.purged, 0, 'sans borne de purge, rien ne disparaît');

      // Purge explicite : les tâches closes antérieures à la borne partent, la journalisation reste.
      const doomed = await user.post(`/api/videos/${asset.id}/jobs`, { kind: 'probe' });
      await user.post(`/api/videos/jobs/${doomed.body.job.id}/cancel`, {});
      const purge = await admin.post('/api/videos/jobs/reap', { purgeBefore: new Date(Date.now() + 60_000).toISOString() });
      assert.equal(purge.status, 200, JSON.stringify(purge.body));
      assert.ok(purge.body.purged >= 1, `purge comptée : ${JSON.stringify(purge.body)}`);
      assert.equal(ctx.runtime.db.get(`SELECT id FROM video_jobs WHERE id = ?`, [doomed.body.job.id]), undefined, 'la ligne close est retirée de la file');
      const trail = await admin.get('/api/admin/audit?limit=30');
      assert.ok((trail.body.items ?? []).some((a) => a.action === 'video.jobs.reap'), 'un ramassage sans trace serait ce que l’audit doit empêcher');
      const bogus = await admin.post('/api/videos/jobs/reap', { purgeBefore: 'lundi prochain' });
      assert.equal(bogus.status, 400, 'une borne illisible est refusée, pas ignorée');
      const purgeDenied = await user.post('/api/videos/jobs/reap', { purgeBefore: new Date().toISOString() });
      assert.equal(purgeDenied.status, 403, 'la purge obéit à videos:manage-jobs');
      const unknown = await user.get('/api/videos/jobs/999999');
      assert.equal(unknown.status, 404);
    });

    it('rattache les artefacts à leur source, et les emporte à la suppression', async () => {
      const child = Buffer.concat([Buffer.from('89504e470d0a1a0a', 'hex'), Buffer.from('0000000d4948445200000001000000010806000000', 'hex'), Buffer.from(String(Date.now()))]);
      ctx.runtime.files.store({ owner: { id: userId }, originalName: 'vignette.png', mimeType: 'image/png', buffer: child, parentFileId: file.id });
      const row = ctx.runtime.db.get(`SELECT id, parent_file_id FROM files WHERE original_name = 'vignette.png'`);
      assert.ok(row, 'l’artefact est stocké');
      assert.equal(row.parent_file_id, file.id);
      const kids = ctx.runtime.files.childrenOf(file.id).map((k) => k.id);
      assert.deepEqual(kids, [row.id]);

      // Le détail HTTP du fichier expose ses artefacts, en même forme que n'importe quel fichier.
      const detail = await user.get(`/api/files/${file.id}`);
      assert.equal(detail.status, 200, JSON.stringify(detail.body));
      assert.equal(detail.body.children.length, 1);
      assert.equal(detail.body.children[0].id, row.id);
      assert.equal(detail.body.children[0].parentId, file.id);
      assert.ok(!('parent_file_id' in detail.body.children[0]), 'la forme interne de la table ne fuit pas dans le bordereau');
      const stranger = await user.get(`/api/files/${row.id}`);
      assert.equal(stranger.status, 200, 'un artefact se lit comme un fichier ordinaire, par sa propre portée');
      const childAbs = path.resolve(ctx.dir, 'uploads', ctx.runtime.db.get(`SELECT relative_path FROM files WHERE id = ?`, [row.id]).relative_path);
      assert.ok(fs.existsSync(childAbs));

      const removed = await user.del(`/api/files/${file.id}`);
      assert.equal(removed.status, 200, JSON.stringify(removed.body));
      const afterDelete = ctx.runtime.db.get(`SELECT deleted_at, parent_file_id FROM files WHERE id = ?`, [row.id]);
      assert.ok(afterDelete.deleted_at, 'l’artefact suit la suppression logique de sa source');
      assert.equal(afterDelete.parent_file_id, file.id);
      assert.ok(!fs.existsSync(childAbs), 'ses octets sont retirés du stockage');
      assert.equal(ctx.runtime.files.childrenOf(file.id).length, 0, 'et il ne reste pas dans la liste des enfants');
    });
  });

  describe('schéma et permissions de la phase B', () => {
    it('a créé la file, le rattachement et les deux permissions, avec les bornes en base', async () => {
      const cols = ctx.runtime.db.all(`SELECT name FROM pragma_table_info('video_jobs')`).map((r) => r.name);
      for (const c of ['locked_by', 'lease_expires_at', 'run_after', 'attempts', 'max_attempts', 'result_json']) {
        assert.ok(cols.includes(c), `colonne ${c} présente`);
      }
      assert.ok(ctx.runtime.db.all(`SELECT name FROM pragma_index_info('idx_video_jobs_claim')`).length > 0, 'l’index de claim existe');
      assert.ok(ctx.runtime.db.all(`SELECT name FROM pragma_table_info('files')`).map((r) => r.name).includes('parent_file_id'));

      const perms = ctx.runtime.db.all(`SELECT key FROM permissions WHERE key LIKE 'videos:%' ORDER BY key`).map((r) => r.key);
      assert.deepEqual(perms, ['videos:manage-jobs', 'videos:process', 'videos:read', 'videos:read:any', 'videos:stream', 'videos:upload']);
      const asUser = await user.get('/api/auth/me');
      const mine = new Set(asUser.body.user.permissions);
      assert.ok(mine.has('videos:stream'), 'un compte standard lit SES vidéos');
      assert.ok(!mine.has('videos:manage-jobs'), 'mais ne pilote pas la file d’autrui');
      assert.ok(!mine.has('videos:read:any'));
    });

    it('refuse en base les valeurs aberrantes de la file', () => {
      const vid = asset.id;
      assert.throws(() =>
        ctx.runtime.db.run(`INSERT INTO video_jobs (video_id, file_id, owner_id, kind, status, attempts, max_attempts, priority) VALUES (?,?,?, 'probe','queued',-1,3,5)`, [vid, file.id, userId]),
      );
      assert.throws(() =>
        ctx.runtime.db.run(`INSERT INTO video_jobs (video_id, file_id, owner_id, kind, status, attempts, max_attempts, priority) VALUES (?,?,?, 'chantier','queued',0,3,5)`, [vid, file.id, userId]),
      );
      assert.throws(() =>
        ctx.runtime.db.run(`INSERT INTO video_jobs (video_id, file_id, owner_id, kind, status, attempts, max_attempts, priority) VALUES (?,?,?, 'probe','queued',0,3,42)`, [vid, file.id, userId]),
      'la priorité est bornée à 0..9');
    });
  });
});
