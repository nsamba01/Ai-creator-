/**
 * Agent Vidéo — phase A : ingestion, sondage d'en-têtes, quarantaine, portée.
 *
 * Les médias sont fabriqués par le test (voir `buildMp4`/`buildWebm`/`buildAvi`
 * dans helpers.js) : de vrais en-têtes de conteneurs, pas des blobs binaires
 * versionnés. `ffprobe` est simulé par un exécuteur injecté — le bac à sable
 * n'a pas le binaire, et un test ne doit rien supposer d'installé.
 */
import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { boot, buildAvi, buildMp4, buildWebm, multipart, PNG_1x1 } from './helpers.js';
import { createVideoService, fromFfprobe, safeBinaryPath } from '../src/services/video.service.js';
import { probeVideoWindows, sniffContainer } from '../src/services/video-probe.js';
import { boundedJson } from '../src/utils/json-limit.js';

const ADMIN = { id: 'admin@test.local', password: 'Sup3r-Secret-Initial!' };
const USER = { id: 'alice@test.local', password: 'User-Standard-2026!' };

async function uploadVideo(client, { name, buffer, mime = 'video/mp4' }) {
  const mp = multipart('file', { filename: name, contentType: mime, buffer });
  return client.post('/api/files', undefined, { headers: mp.headers, form: mp.body });
}

describe('agent vidéo (phase A)', () => {
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

  async function enable({ maxDuration = 3600 } = {}) {
    const res = await admin.put('/api/admin/settings', { entries: { 'video.enabled': true, 'video.max_duration_seconds': maxDuration } });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.deepEqual(res.body.rejected, [], 'les deux clés sont connues et bornées');
  }

  it('refuse toute déclaration tant que la fonctionnalité est éteinte', async () => {
    const up = await uploadVideo(user, { name: 'seance.mp4', buffer: buildMp4() });
    assert.equal(up.status, 201, JSON.stringify(up.body));
    const fileId = up.body.file.id;
    const res = await user.post('/api/videos', { fileId });
    assert.equal(res.status, 409, 'l’interrupteur administrateur commande l’accès');
    assert.equal(res.body.error.code, 'VIDEO_FEATURE_DISABLED');
    assert.match(res.body.error.message, /video\.enabled/);
    assert.equal(ctx.runtime.db.get(`SELECT count(*) AS c FROM video_assets`).c, 0, 'aucune ligne créée');
  });

  it('accepte un MP4 réel et restitue la géométrie annoncée par le conteneur', async () => {
    await enable();
    const up = await uploadVideo(user, { name: 'conference.mp4', buffer: buildMp4({ durationMs: 4000, width: 1280, height: 720 }) });
    const fileId = up.body.file.id;
    assert.equal(up.body.file.kind, 'video', 'classé comme vidéo par le pipeline de fichiers');

    const res = await user.post('/api/videos', { fileId });
    assert.equal(res.status, 201, JSON.stringify(res.body));
    const asset = res.body.asset;
    assert.equal(asset.status, 'ready');
    assert.equal(asset.durationMs, 4000);
    assert.equal(asset.width, 1280);
    assert.equal(asset.height, 720);
    assert.equal(asset.codec, 'avc1');
    assert.equal(asset.fps, 25);
    assert.equal(asset.parser, 'iso-bmff');
    assert.ok(['header', 'header+ffprobe'].includes(asset.probeSource), `sondé depuis ${asset.probeSource}`);
    assert.ok(asset.bitrateBps > 0, 'débit estimé à partir de la taille et de la durée');
    assert.equal(res.body.task.agentRole, 'video', 'la tâche de l’agent est tracée');
  });

  it('sonde WebM (EBML) avec deux pistes et le codec de la piste vidéo', async () => {
    const up = await uploadVideo(user, { name: 'capture.webm', mime: 'video/webm', buffer: buildWebm({ width: 640, height: 360, durationMs: 3200 }) });
    const res = await user.post('/api/videos', { fileId: up.body.file.id });
    assert.equal(res.status, 201, JSON.stringify(res.body));
    const a = res.body.asset;
    assert.equal(a.container, 'matroska');
    assert.equal(a.brand, 'webm', 'le DocType EBML sert de marque');
    assert.equal(a.durationMs, 3200);
    assert.equal(a.width, 640);
    assert.equal(a.height, 360);
    assert.equal(a.codec, 'V_VP8');
    assert.equal(a.trackCount, 2);
    const streams = a.meta.streams;
    assert.deepEqual(streams.map((s) => s.type).sort(), ['audio', 'video'], 'les deux pistes sont restituées');
  });

  it('sonde AVI (RIFF) à partir des en-têtes de flux', async () => {
    const up = await uploadVideo(user, { name: 'ancien.avi', mime: 'video/x-msvideo', buffer: buildAvi({ frames: 100, microSecPerFrame: 40_000, width: 640, height: 480 }) });
    const res = await user.post('/api/videos', { fileId: up.body.file.id });
    assert.equal(res.status, 201, JSON.stringify(res.body));
    const a = res.body.asset;
    assert.equal(a.container, 'avi');
    assert.equal(a.durationMs, 4000, '100 images à 25/s');
    assert.equal(a.fps, 25);
    assert.equal(a.codec, 'DIVX');
    assert.equal(a.parser, 'riff');
  });

  it('relit un MP4 dont la table « moov » est écrite en fin de fichier', async () => {
    const up = await uploadVideo(user, { name: 'non-faststart.mp4', buffer: buildMp4({ tailMode: true, durationMs: 6000, width: 1920, height: 1080 }) });
    const res = await user.post('/api/videos', { fileId: up.body.file.id });
    assert.equal(res.status, 201, JSON.stringify(res.body));
    const a = res.body.asset;
    assert.equal(a.status, 'ready', 'la fenêtre de queue a suffi à trouver la table');
    assert.equal(a.durationMs, 6000);
    assert.equal(a.width, 1920);
    assert.equal(a.height, 1080);
  });

  it('refuse un faux .mp4 dès le téléversement : la signature commande', async () => {
    const res = await uploadVideo(user, { name: 'faux.mp4', buffer: Buffer.from('ceci n’est pas un conteneur mp4, juste du texte.', 'utf8') });
    assert.equal(res.status, 415, JSON.stringify(res.body));
    assert.match(JSON.stringify(res.body), /signature|contenu refusé/i);
  });

  it('refuse un PNG renommé .mp4 à l’ingestion vidéo directe', async () => {
    const mp = multipart('file', { filename: 'image.mp4', contentType: 'image/png', buffer: PNG_1x1 });
    const res = await user.post('/api/videos/upload', undefined, { headers: mp.headers, form: mp.body });
    assert.equal(res.status, 415, 'le filtre de conteneur s’applique avant toute écriture');
    assert.ok(
      ['VIDEO_UNSUPPORTED_CONTAINER', 'UNSUPPORTED_MEDIA_TYPE'].includes(res.body.error.code),
      `code de refus attendu, reçu ${res.body.error.code}`,
    );
    assert.equal(ctx.runtime.db.get(`SELECT count(*) AS c FROM video_assets WHERE file_id IN (SELECT id FROM files WHERE original_name = 'image.mp4')`).c, 0, 'rien n’est stocké ni déclaré');
  });

  it('met en quarantaine une durée hors limite et exige videos:process pour la relancer', async () => {
    await enable({ maxDuration: 60 });
    const up = await uploadVideo(user, { name: 'marathon.mp4', buffer: buildMp4({ durationMs: 90_000 }) });
    const res = await user.post('/api/videos', { fileId: up.body.file.id });
    assert.equal(res.status, 201, JSON.stringify(res.body));
    const a = res.body.asset;
    assert.equal(a.status, 'quarantined', 'le rapport n’est pas diffusé comme une vidéo saine');
    assert.equal(a.errorCode, 'VIDEO_DURATION_EXCEEDED');
    assert.ok(a.notes.some((n) => /limite/.test(n)), 'la note explique le refus');
    assert.equal(a.container, 'mp4', 'le refus ne doit pas effacer ce qui a été lu');
    assert.equal(a.width, 1280);
    assert.equal(a.height, 720);
    assert.equal(a.parser, 'iso-bmff');
    assert.equal(a.probeSource, 'header', 'la colonne dit la vérité sur le lecteur qui a travaillé');

    const denied = await user.post(`/api/videos/${a.id}/probe`, {});
    assert.equal(denied.status, 403, 'sortir de quarantaine n’est pas un droit d’auto-service');
    assert.match(denied.body.error.message, /videos:process/);

    const released = await admin.post(`/api/videos/${a.id}/release`, {});
    assert.equal(released.status, 200, JSON.stringify(released.body));
    assert.equal(released.body.asset.status, 'ready');

    // La limite est remise à une valeur normale pour la suite du fichier de test.
    await enable({ maxDuration: 3600 });
  });

  it('ne permet pas à un compte standard de lire la vidéo d’un autre', async () => {
    const up = await uploadVideo(admin, { name: 'prive.mp4', buffer: buildMp4() });
    const declared = await admin.post('/api/videos', { fileId: up.body.file.id });
    assert.equal(declared.status, 201, JSON.stringify(declared.body));
    const id = declared.body.asset.id;

    const mine = await user.get(`/api/videos/${id}`);
    assert.equal(mine.status, 403, 'portée stricte même en devinant l’identifiant');
    const listed = await user.get('/api/videos');
    assert.equal(listed.status, 200);
    assert.equal(listed.body.scope, 'own');
    assert.ok(!listed.body.items.some((v) => v.id === id), 'la liste ne fuit pas');

    const asAdmin = await admin.get(`/api/videos/${id}`);
    assert.equal(asAdmin.status, 200, 'ADMIN détient videos:read:any');
    const all = await admin.get('/api/videos');
    assert.equal(all.body.scope, 'all');
    assert.ok(all.body.items.some((v) => v.id === id));
  });

  it('refuse un identifiant inconnu et un fichier d’autrui, sans détail technique', async () => {
    const missing = await user.post('/api/videos', { fileId: 999999 });
    assert.equal(missing.status, 404, JSON.stringify(missing.body));
    assert.equal(missing.body.error.code, 'NOT_FOUND');

    const adminFile = await uploadVideo(admin, { name: 'prive-source.mp4', buffer: buildMp4({ mdatSize: 1536, durationMs: 2500 }) });
    const stolen = await user.post('/api/videos', { fileId: adminFile.body.file.id });
    assert.equal(stolen.status, 403, 'même comportement que le pipeline de fichiers');
    assert.match(stolen.body.error.message, /autre utilisateur/);
    assert.ok(!JSON.stringify(stolen.body).match(/\/(home|app|var|tmp)\//), 'aucun chemin du serveur dans la réponse');
  });

  it('reste idempotent : redéclarer le même fichier ne duplique ni ligne ni octet', async () => {
    const up = await uploadVideo(user, { name: 'doublon.mp4', buffer: buildMp4({ mdatSize: 3072, durationMs: 5000 }) });
    const first = await user.post('/api/videos', { fileId: up.body.file.id });
    assert.equal(first.status, 201);
    const second = await user.post('/api/videos', { fileId: up.body.file.id });
    assert.equal(second.status, 200, 'déjà enregistré : 200, pas de seconde création');
    assert.equal(second.body.alreadyRegistered, true);
    const rows = ctx.runtime.db.get(`SELECT count(*) AS c FROM video_assets WHERE file_id = ?`, [up.body.file.id]).c;
    assert.equal(rows, 1);
    const analyses = ctx.runtime.db.get(`SELECT count(*) AS c FROM video_analyses WHERE video_id = ?`, [first.body.asset.id]).c;
    assert.equal(analyses, 1, 'une seule analyse « probe » par vidéo');
  });

  it('re-sonde sans dupliquer le rapport', async () => {
    const up = await uploadVideo(user, { name: 'reprobe.mp4', buffer: buildMp4() });
    const first = await user.post('/api/videos', { fileId: up.body.file.id });
    const id = first.body.asset.id;
    const again = await user.post(`/api/videos/${id}/probe`, {});
    assert.equal(again.status, 200, JSON.stringify(again.body));
    assert.equal(again.body.analyses.length, 1, 'le rapport est remplacé, pas empilé');
    assert.equal(again.body.analyses[0].kind, 'probe');
    assert.ok(Number.isFinite(again.body.analyses[0].costMs), 'la coût du sondage est mesuré');
  });

  it('signale la collecte par URL comme non implémentée plutôt que de la deviner', async () => {
    const res = await user.post('/api/videos/from-url', { url: 'https://exemple.fr/secret.mp4' });
    assert.equal(res.status, 501);
    assert.equal(res.body.error.code, 'VIDEO_URL_NOT_IMPLEMENTED');
    assert.match(res.body.error.message, /phase B/);
    assert.ok(!JSON.stringify(res.body).includes('exemple.fr'), 'l’URL n’est pas renvoyée dans l’erreur');
  });

  it('n’expose ni chemin de stockage ni empreinte complète', async () => {
    const up = await uploadVideo(user, { name: 'fuite.mp4', buffer: buildMp4() });
    const declared = await user.post('/api/videos', { fileId: up.body.file.id });
    const detail = await user.get(`/api/videos/${declared.body.asset.id}`);
    assert.equal(detail.status, 200);
    const body = JSON.stringify(detail.body);
    assert.ok(!/\/(home|app|var|tmp)\//.test(body), 'aucun chemin absolu');
    assert.ok(!body.includes('relative_path') && !body.includes('stored_name'), 'le nommage interne reste privé');
    assert.equal(detail.body.asset.sha256.length, 16, 'l’empreinte est tronquée');
  });

  it('suit la suppression logique du fichier source', async () => {
    const up = await uploadVideo(user, { name: 'a-supprimer.mp4', buffer: buildMp4() });
    const declared = await user.post('/api/videos', { fileId: up.body.file.id });
    const id = declared.body.asset.id;
    const del = await user.del(`/api/files/${up.body.file.id}`);
    assert.equal(del.status, 200, JSON.stringify(del.body));
    const gone = await user.get(`/api/videos/${id}`);
    assert.equal(gone.status, 404, 'la vidéo n’est plus atteignable une fois sa source supprimée');
    const listed = await user.get('/api/videos');
    assert.ok(!listed.body.items.some((v) => v.id === id));
  });

  it('fusionne un rapport ffprobe injecté et n’envoie jamais le nom client dans la commande', async () => {
    const calls = [];
    const service = createVideoService({
      db: ctx.runtime.db,
      config: ctx.runtime.config,
      audit: ctx.runtime.audit,
      files: ctx.runtime.files,
      agents: ctx.runtime.agents,
      settings: ctx.runtime.settings,
      ffprobeRunner: (bin, args) => {
        calls.push({ bin, args });
        return {
          ok: true,
          json: {
            format: { format_name: 'mov,mp4,m4a', duration: '12.5', bit_rate: '4800000', brand: 'qt  ' },
            streams: [
              { index: 0, codec_type: 'video', codec_name: 'hevc', width: 3840, height: 2160, avg_frame_rate: '30000/1001' },
              { index: 1, codec_type: 'audio', codec_name: 'aac' },
            ],
          },
        };
      },
    });
    const up = await uploadVideo(user, { name: '-vf.mp4', buffer: buildMp4({ width: 1280, height: 720 }) });
    const fileId = up.body.file.id;
    const { abs } = ctx.runtime.files.readAbsolute(fileId);
    const out = service.probeFile(abs, up.body.file.sizeBytes);
    assert.equal(out.ok, true);
    assert.equal(out.width, 3840, 'ffprobe complète l’en-tête quand il est muet sur la résolution réelle');
    assert.equal(out.height, 2160);
    assert.equal(out.codec, 'hevc');
    assert.equal(out.durationMs, 12500);
    assert.equal(out.bitrateBps, 4_800_000);
    assert.equal(Math.round(out.fps * 1000), 29970, '30000/1001 ≈ 29,970');

    assert.equal(calls.length, 1);
    assert.ok(calls[0].args.includes('-i'), 'l’option d’entrée est explicite');
    assert.equal(calls[0].args[calls[0].args.indexOf('-i') + 1], abs, 'seul le chemin de stockage, absolu, est passé');
    assert.ok(!calls[0].args.some((a) => String(a).includes('-vf')), 'le nom d’origine du fichier n’atteint jamais la ligne de commande');
    assert.equal(calls[0].bin, 'ffprobe');
  });

  it('se replie proprement quand ffprobe répond « binaire absent »', async () => {
    const service = createVideoService({
      db: ctx.runtime.db,
      config: ctx.runtime.config,
      audit: ctx.runtime.audit,
      files: ctx.runtime.files,
      agents: ctx.runtime.agents,
      settings: ctx.runtime.settings,
      ffprobeRunner: () => ({ ok: false, reason: 'binaire absent' }),
    });
    const up = await uploadVideo(user, { name: 'repli.mp4', buffer: buildMp4() });
    const { abs } = ctx.runtime.files.readAbsolute(up.body.file.id);
    const out = service.probeFile(abs, up.body.file.sizeBytes);
    assert.equal(out.ok, true, 'le sondage d’en-têtes reste valable seul');
    assert.ok(out.notes.some((n) => /ffprobe indisponible/.test(n)), 'le repli est dit, pas masqué');
  });

  it('valide le chemin du binaire avant toute exécution', () => {
    assert.equal(safeBinaryPath(process.execPath), process.execPath, 'un binaire réel et exécutable passe');
    const ff = safeBinaryPath('ffprobe');
    assert.ok(ff === null || ff.endsWith('/ffprobe'), 'un nom simple vaut s’il est résolu dans PATH, sinon null');
    assert.equal(safeBinaryPath('/usr/bin/ffprobe-qui-n-existe-pas'), null, 'absent = refusé');
    assert.equal(safeBinaryPath('ffprobe; rm -rf /'), null, 'aucun métacaractère');
    assert.equal(safeBinaryPath('../../etc/passwd'), null, 'aucune traversée');
    assert.equal(safeBinaryPath(''), null);
    assert.equal(safeBinaryPath('bin/ffprobe'), null, 'un chemin relatif avec barre est refusé');
    assert.equal(safeBinaryPath('/etc/shadow'), null, 'un fichier non exécutable est refusé');
  });

  it('convertit la sortie ffprobe avec des bornes, jamais des valeurs brutes', () => {
    const out = fromFfprobe({
      format: { format_name: 'matroska,webm', duration: '70', nb_streams: 2 },
      streams: [{ codec_type: 'video', codec_name: 'vp9', width: 999999, height: -3, avg_frame_rate: '0/0', r_frame_rate: '24000/1001' }],
    });
    assert.equal(out.container, 'matroska');
    assert.equal(out.durationMs, 70000);
    assert.equal(out.width, null, 'une largeur aberrante n’est pas stockée');
    assert.equal(out.height, null);
    assert.equal(out.fps, 23.976, 'le débit de repli r_frame_rate est utilisé si avg est nul');
    assert.equal(out.codec, 'vp9');
    assert.equal(fromFfprobe(null).trackCount, 0, 'une réponse vide ne fait pas tomber le sondage');
  });

  it('refuse en base les valeurs aberrantes (contraintes CHECK effectives)', () => {
    const file = ctx.runtime.db.get(`SELECT * FROM files WHERE kind = 'video' ORDER BY id DESC LIMIT 1`);
    assert.ok(file, 'au moins une vidéo a été téléversée par les tests précédents');
    assert.throws(
      () => ctx.runtime.db.run(`INSERT INTO video_assets (file_id, owner_id, duration_ms, status, probe_source) VALUES (?,?,?,'pending','none')`, [file.id + 77, file.owner_id, 999_999_999]),
      /CHECK|constraint/i,
      'une durée impossible est refusée par le schéma, pas seulement par le service',
    );
    assert.throws(() => ctx.runtime.db.run(`INSERT INTO video_assets (file_id, owner_id, width, status, probe_source) VALUES (?,?,?,'pending','none')`, [file.id + 78, file.owner_id, 20000]), /CHECK|constraint/i);
  });

  it('journalise le sondage sans chemin technique', () => {
    const row = ctx.runtime.db.get(`SELECT * FROM audit_logs WHERE action IN ('video.probed','video.registered','video.quarantined') ORDER BY id DESC LIMIT 1`);
    assert.ok(row, 'l’événement est tracé');
    assert.ok(['success', 'blocked'].includes(row.outcome));
    const detail = row.detail_json ?? '';
    assert.ok(!/\/(home|app|var|tmp)\//.test(detail), 'le détail ne contient pas de chemin du serveur');
    assert.ok(row.target_type === 'video' || row.target_type === null);
  });

  it('sonde les conteneurs inconnus sans exception et sans faux positif', () => {
    const junk = Buffer.concat([Buffer.from('ftyp'.padStart(8, '\0')), Buffer.alloc(4096, 0x7a)]);
    const sniff = sniffContainer(junk);
    assert.equal(sniff.container, 'mp4', 'la signature suffit à classer');
    const out = probeVideoWindows(junk, null, { bytes: 4096 });
    assert.equal(out.ok, false);
    assert.equal(out.errorCode, 'VIDEO_HEADER_INCOMPLETE', 'aucune métadonnée inventée');
    assert.ok(out.notes.some((n) => /ffprobe/.test(n)), 'la note oriente vers la solution');
    const ogg = probeVideoWindows(Buffer.concat([Buffer.from('OggS'), Buffer.alloc(64)]), null, {});
    assert.equal(ogg.errorCode, 'VIDEO_UNSUPPORTED_CONTAINER');
  });

  it('expose la posture de l’agent (compteurs et réglages effectifs)', async () => {
    const stats = await user.get('/api/videos/stats');
    assert.equal(stats.status, 200);
    assert.equal(stats.body.enabled, true);
    assert.ok(stats.body.count >= 1);
    assert.equal(stats.body.limits.maxDurationMs, 3600_000);
    assert.ok(stats.body.limits.maxBytes > 0);
    assert.ok(Array.isArray(stats.body.byStatus));
    assert.equal(typeof stats.body.ffprobeConfigured, 'boolean');
  });

  it('ne déclare jamais prête une vidéo levée de quarantaine sans sondage', async () => {
    const up = await uploadVideo(user, { name: 'jamais-sondee.mp4', buffer: buildMp4({ mdatSize: 2048, durationMs: 1200 }) });
    const created = await user.post('/api/videos', { fileId: up.body.file.id });
    assert.equal(created.status, 201, JSON.stringify(created.body));
    const id = created.body.asset.id;
    await admin.post(`/api/videos/${id}/quarantine`, { reason: 'preuve' });
    const released = await admin.post(`/api/videos/${id}/release`, {});
    assert.equal(released.status, 200);
    assert.ok(['ready', 'pending'].includes(released.body.asset.status), `état ${released.body.asset.status}`);
    const probed = await admin.post(`/api/videos/${id}/probe`, {});
    assert.equal(probed.body.asset.status, 'ready', 'le re-sondage est ce qui rend la vidéo prête');
  });

  it('n’écrit jamais un texte qui ne se relit pas dans la colonne', () => {
    const repo = ctx.runtime.videos.repo;
    const asset = ctx.runtime.db.get(`SELECT id FROM video_assets ORDER BY id LIMIT 1`);
    assert.ok(asset, 'une vidéo existe déjà à ce stade du parcours');
    // Volontairement illisible et surdimensionné : le dépôt doit déclarer la perte,
    // au lieu d’écrire du JSON découpé que plus personne ne relirait.
    const broken = '{"notes": ["' + 'y'.repeat(20_000);
    repo.applyProbe(asset.id, { container: 'mp4', status: 'ready', probeSource: 'header', metaJson: broken });
    const row = ctx.runtime.db.get(`SELECT meta_json AS m FROM video_assets WHERE id = ?`, [asset.id]);
    assert.ok(row.m.length <= 16_000, `taille ${row.m.length}`);
    const parsed = JSON.parse(row.m);
    assert.equal(parsed.truncated, true, 'le dépôt doit signaler la réduction au lieu d’écrire du JSON cassé');
    assert.equal(typeof parsed.note, 'string');
  });
});

describe('bornage des rapports stockés (JSON jamais cassé)', () => {
  it('laisse intact un rapport qui tient sous la borne', () => {
    const meta = { container: 'mp4', codec: 'avc1', streams: [{ type: 'video', width: 1920 }], notes: ['ok'] };
    const json = boundedJson(meta, 16_000);
    assert.deepEqual(JSON.parse(json), meta);
  });

  it('réduit un rapport démesuré sans le rendre illisible', () => {
    const meta = {
      container: 'webm',
      notes: Array.from({ length: 400 }, (_, i) => `note ${i} — ${'x'.repeat(400)}`),
      streams: Array.from({ length: 4000 }, (_, i) => ({ type: 'video', id: i, codec: `V_FAKE${'y'.repeat(200)}` })),
    };
    const json = boundedJson(meta, 16_000);
    assert.ok(json.length <= 16_000, `taille ${json.length}`);
    const back = JSON.parse(json);
    assert.equal(back.truncated, true, 'la réduction doit être déclarée, pas silencieuse');
    assert.ok(Array.isArray(back.streams) && back.streams.length > 0, 'une partie du rapport reste lisible');
    assert.ok(back.streams.length < 4000);
  });

  it('reste sous la borne même pour un objet non réductible', () => {
    const json = boundedJson('z'.repeat(200_000), 200);
    assert.ok(json.length <= 200, `taille ${json.length}`);
    assert.doesNotThrow(() => JSON.parse(json));
  });

});

