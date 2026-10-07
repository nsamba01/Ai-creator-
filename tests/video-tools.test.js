/**
 * Phase C de l'agent vidéo : exécution d'un outil média hors du processus web.
 *
 * `ffmpeg` n'existe pas dans cet environnement (et n'y sera pas installé). Les tests utilisent donc
 * un **shim POSIX déterministe** — un script `/bin/sh` qui joue le rôle de l'outil : il lit un mode
 * dans un fichier témoin voisin, écrit (ou ne écrit pas) sa sortie, et meurt quand on l'attend trop
 * longtemps. Ce n'est pas un faux succès : tout ce qui est sous vérification est **notre** code —
 * construction de la ligne de commande, résolution du binaire, délai, plafond de sortie, validation
 * de signature, rattachement de l'artefact, refus nommés. Un faux `ffmpeg` qui se comporte mal prouve
 * exactement la même chose qu'un vrai qui se comporte mal.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { boot, buildMp4, multipart } from './helpers.js';
import { audioArgs, createFfmpegRunner, isPng, makeScratch, thumbnailArgs } from '../src/services/video-ffmpeg.js';
import { createVideoMediaService } from '../src/services/video-media.service.js';
import { createVideoJobRunner } from '../src/services/video-jobs.service.js';

const ADMIN = { id: 'admin@test.local', password: 'Sup3r-Secret-Initial!' };
const USER = { id: 'alice@test.local', password: null };

const SHIM = `#!/bin/sh
# Shim ffmpeg pour tests : mode lu dans "<entree>.shim" (ok|fail|hang|noise|huge|empty).
last=""
in=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-i" ]; then in="$a"; fi
  prev="$a"
  last="$a"
done
mode="ok"
if [ -f "$in.shim" ]; then mode=$(cat "$in.shim"); fi
case "$mode" in
  hang)
    sleep 30
    exit 0
    ;;
  fail)
    echo "ffmpeg: erreur de lecture $in : Invalid argument" >&2
    exit 83
    ;;
  noise)
    printf 'ce-ci n est pas une image' > "$last"
    exit 0
    ;;
  empty)
    : > "$last"
    exit 0
    ;;
  huge)
    head -c 300000 /dev/zero | tr '\\0' 'A' > "$last"
    exit 0
    ;;
  wav)
    printf 'RIFF' > "$last"
    head -c 4 /dev/zero >> "$last"
    printf 'WAVEfmt ' >> "$last"
    head -c 200 /dev/zero >> "$last"
    exit 0
    ;;
  *)
    printf '\\211PNG\\015\\012\\032\\012' > "$last"
    head -c 4096 /dev/zero >> "$last"
    exit 0
    ;;
esac
`;

let shimDir;
let shimPath;

before(() => {
  shimDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-shim-'));
  shimPath = path.join(shimDir, 'ffmpeg');
  fs.writeFileSync(shimPath, SHIM, { mode: 0o755 });
});

after(() => {
  fs.rmSync(shimDir, { recursive: true, force: true });
});

/**
 * Like `assert.rejects`, but also covers methods that throw synchronously
 * (the service gates do: they validate before any async work).
 */
async function rejects(fn, predicate, message) {
  return assert.rejects(async () => { await fn(); }, predicate, message);
}

async function uploadVideo(client, { name, buffer, mime = 'video/mp4' }) {
  const mp = multipart('file', { filename: name, contentType: mime, buffer });
  return client.post('/api/files', undefined, { headers: mp.headers, form: mp.body });
}

/** Écrit le fichier témoin qui pilote le shim, à côté de l'entrée. */
function setMode(inputPath, mode) {
  if (mode === null) {
    fs.rmSync(`${inputPath}.shim`, { force: true });
    return;
  }
  fs.writeFileSync(`${inputPath}.shim`, mode);
}

describe('outillage média (phase C)', () => {
  describe('ligne de commande de l’outil', () => {
    it('ne contient aucun mot venant du client', () => {
      const evil = '../../etc/shadow; echo $(rm -rf /) " .mp4';
      const args = thumbnailArgs({ abs: '/app/data/uploads/uuid.mp4', out: '/tmp/ps-thumb/x.png', atMs: evil, width: evil });
      const joined = args.join(' ');
      assert.ok(!joined.includes('shadow'), 'un nom de fichier client n’atteint jamais argv');
      assert.ok(!joined.includes('rm -rf'), 'aucun fragment injectable');
      assert.ok(!joined.includes(';'), 'aucun séparateur de commande');
      assert.equal(args[0], '-hide_banner');
      assert.equal(args[args.length - 1], '/tmp/ps-thumb/x.png', 'la sortie est le dernier argument, exactement un chemin interne');
      assert.ok(args.includes('/app/data/uploads/uuid.mp4'));
      // Valeurs aberrantes → bornes par défaut, jamais NaN ni nombre négatif dans `-ss`.
      const ss = args[args.indexOf('-ss') + 1];
      assert.equal(ss, '1.000');
      assert.match(args[args.indexOf('-vf') + 1], /^scale=320:-2/);
    });

    it('borne durée, largeur et échantillonnage des deux côtés', () => {
      const wide = thumbnailArgs({ abs: '/a', out: '/b', atMs: 1e15, width: 100_000 });
      assert.match(wide[wide.indexOf('-vf') + 1], /^scale=1920:-2/, 'largeur écrêtée à 1920');
      assert.equal(wide[wide.indexOf('-ss') + 1], '86400.000', 'la position est écrêtée à 24 h, pas multipliée');
      assert.equal(thumbnailArgs({ abs: '/a', out: '/b', atMs: -50, width: 1 }).join(' ').includes('-ss 0.000'), true, 'position négative ramenée à 0');
      const a = audioArgs({ abs: '/a', out: '/b', maxSeconds: 999_999, sampleRate: 1, channels: 9 });
      assert.equal(a[a.indexOf('-t') + 1], '3600');
      assert.equal(a[a.indexOf('-ar') + 1], '8000', 'un échantillonnage absurde retombe sur la borne basse');
      assert.equal(a[a.indexOf('-ac') + 1], '2');
      assert.throws(() => thumbnailArgs({ abs: '', out: '/b' }), /incomplets/);
      assert.throws(() => audioArgs({ abs: '/a' }), /incomplets/);
    });

    it('reconnaît un PNG et refuse ce qui n’en est pas un', () => {
      assert.ok(isPng(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0])));
      assert.ok(!isPng(Buffer.from('GIF89a')));
      assert.ok(!isPng(Buffer.alloc(3)));
    });

    it('fabrique un répertoire de travail fermé et n’en laisse pas sortir ses fichiers', () => {
      const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-scratch-'));
      try {
        const scratch = makeScratch({ root });
        const st = fs.statSync(scratch.dir);
        assert.equal(st.mode & 0o777, 0o700, 'le répertoire de travail n’est lisible par personne d’autre');
        assert.ok(scratch.file('a.png').startsWith(scratch.dir));
        // Une tentative d'évasion par le nom est neutralisée, pas résolue.
        const escaped = scratch.file('../../etc/passwd');
        assert.ok(path.resolve(escaped).startsWith(scratch.dir + path.sep), `le nom asséchi reste dans le répertoire de travail : ${escaped}`);
        scratch.dispose();
        assert.ok(!fs.existsSync(scratch.dir));
      } finally {
        fs.rmSync(root, { recursive: true, force: true });
      }
    });
  });

  describe('lanceur réel (shim POSIX)', () => {
    let tmp;
    let input;

    before(() => {
      tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-run-'));
      input = path.join(tmp, 'entree.mp4');
      fs.writeFileSync(input, 'vidéo factice pour shim');
    });
    after(() => fs.rmSync(tmp, { recursive: true, force: true }));

    const runWith = (opts = {}) => createFfmpegRunner({ timeoutMs: 1500, ...opts });

    it('rend le fichier quand l’outil réussit, et le borne à la taille demandée', () => {
      const scratch = makeScratch({ root: tmp });
      const out = scratch.file('v.png');
      setMode(input, 'ok');
      try {
        const res = runWith().run({ bin: shimPath, args: ['-i', input, out], outPath: out, maxOutBytes: 64 * 1024 });
        assert.equal(res.ok, true, JSON.stringify(res));
        assert.ok(isPng(res.buffer), 'la sortie est relue et renvoyée en mémoire');
        assert.equal(res.bytes, 8 + 4096);
      } finally {
        scratch.dispose();
      }
    });

    it('refuse une sortie trop volumineuse et la retire du disque', () => {
      const scratch = makeScratch({ root: tmp });
      const out = scratch.file('v.png');
      setMode(input, 'huge');
      try {
        const res = runWith().run({ bin: shimPath, args: ['-i', input, out], outPath: out, maxOutBytes: 4096 });
        assert.equal(res.ok, false);
        assert.equal(res.code, 'VIDEO_TOOL_OUTPUT_REFUSED');
        assert.match(res.reason, /300000 octets pour un plafond de 4096/);
        assert.ok(!fs.existsSync(out), 'le poids refusé ne reste pas sur le disque');
      } finally {
        scratch.dispose();
      }
    });

    it('arrache le délai par SIGKILL et le dit, au lieu d’attendre l’outil', () => {
      const scratch = makeScratch({ root: tmp });
      const out = scratch.file('v.png');
      setMode(input, 'hang');
      const started = Date.now();
      try {
        const res = runWith({ timeoutMs: 1000 }).run({ bin: shimPath, args: ['-i', input, out], outPath: out });
        const elapsed = Date.now() - started;
        assert.equal(res.ok, false);
        assert.ok(elapsed < 8000, `le délai est appliqué (${elapsed} ms)`);
        assert.match(res.reason, /signal|délai/, res.reason);
      } finally {
        scratch.dispose();
      }
    });

    it('traduit un code de sortie non nul sans recopier le chemin de stockage', () => {
      const scratch = makeScratch({ root: tmp });
      const out = scratch.file('v.png');
      setMode(input, 'fail');
      try {
        const res = runWith().run({ bin: shimPath, args: ['-i', input, out], outPath: out });
        assert.equal(res.ok, false);
        assert.equal(res.code, 'VIDEO_TOOL_FAILED');
        assert.match(res.reason, /a répondu 83/);
        assert.ok(!/\/(tmp|home|app|var)\//.test(res.detail ?? ''), `stderr assaini : ${res.detail}`);
        assert.match(String(res.detail), /chemin masqué/);
      } finally {
        scratch.dispose();
      }
    });

    it('refuse un binaire non résolu, des arguments douteux, et une sortie absente ou vide', () => {
      const scratch = makeScratch({ root: tmp });
      const missing = path.join(tmp, 'inexistant.png');
      assert.equal(runWith().run({ bin: null, args: ['-i', input, missing], outPath: missing }).code, 'VIDEO_TOOL_UNAVAILABLE');
      assert.equal(runWith().run({ bin: 'ffmpeg-qui-n-existe-pas', args: ['-i', input, missing], outPath: missing }).code, 'VIDEO_TOOL_UNAVAILABLE');
      assert.equal(runWith().run({ bin: shimPath, args: ['-i', input, 'with\0nul'], outPath: missing }).code, 'VIDEO_TOOL_FAILED');
      setMode(input, 'empty');
      try {
        const res = runWith().run({ bin: shimPath, args: ['-i', input, scratch.file('vide.png')], outPath: scratch.file('vide.png') });
        assert.equal(res.ok, false, 'une sortie de zéro octet n’est pas un succès');
        assert.match(res.reason, /vide/);
      } finally {
        setMode(input, null);
        scratch.dispose();
      }
    });

    it('ne passe jamais par une coquille : le nom du fichier témoin ne peut pas exécuter de commande', () => {
      // Preuve négative : un « nom de sortie » porteur de métacaractères n'est pas interprété.
      const tricky = path.join(tmp, "$(touch powneed).png");
      const res = runWith().run({ bin: shimPath, args: ['-i', input, tricky], outPath: tricky, maxOutBytes: 64 * 1024 });
      assert.ok(res.ok === true || res.code === 'VIDEO_TOOL_OUTPUT_REFUSED' || res.code === 'VIDEO_TOOL_FAILED');
      assert.ok(!fs.existsSync(path.join(tmp, 'powneed')), 'aucune commande secondaire exécutée');
      fs.rmSync(tricky, { force: true });
    });
  });

  describe('service de média : les portes avant l’octet', () => {
    let ctx;
    let admin;
    let user;
    let asset;
    let storedFile;
    let media;

    before(async () => {
      ctx = await boot({ extraConfig: { FFMPEG_PATH: shimPath } });
      admin = ctx.client();
      user = ctx.client();
      await admin.login(ADMIN.id, ADMIN.password);
      await user.login(USER.id, ctx.standardPassword);
      await admin.put('/api/admin/settings', {
        entries: { 'video.enabled': true, 'video.tools_enabled': true, 'video.async_probe': false, 'video.thumbnail_max_kb': 64 },
      });
      const up = await uploadVideo(user, { name: 'source-avec-vignette.mp4', buffer: buildMp4({ durationMs: 2000, mdatSize: 4096 }) });
      assert.equal(up.status, 201, JSON.stringify(up.body));
      storedFile = up.body.file;
      const declared = await user.post('/api/videos', { fileId: storedFile.id });
      assert.equal(declared.status, 201, JSON.stringify(declared.body));
      asset = declared.body.asset;
      media = ctx.runtime.videoMedia;
    });

    after(async () => {
      await ctx.close();
    });

    const rowOf = (id) => ctx.runtime.db.get(`SELECT * FROM video_assets WHERE id = ?`, [id]);
    const fileRow = () => ctx.runtime.db.get(`SELECT * FROM files WHERE id = ?`, [storedFile.id]);
    const inputPath = () => ctx.runtime.files.resolveStored(fileRow().relative_path);

    it('refuse tout traitement tant que video.tools_enabled est fermé', async () => {
      await admin.put('/api/admin/settings', { key: 'video.tools_enabled', value: false });
      try {
        await rejects(() => media.thumbnail({ videoId: asset.id }), (err) => {
          assert.equal(err.status, 409);
          assert.equal(err.code, 'VIDEO_TOOLS_DISABLED');
          assert.match(err.message, /video\.tools_enabled/);
          return true;
        });
      } finally {
        await admin.put('/api/admin/settings', { key: 'video.tools_enabled', value: true });
      }
      assert.equal(media.toolsEnabled(), true);
      // Un refus de porte est un événement : « le worker n'a rien fait » et « le worker a refusé
      // parce que la capacité est fermée » ne doivent pas se ressembler dans le journal.
      const trail = await admin.get('/api/admin/audit?limit=40');
      const row = (trail.body.items ?? []).find((a) => a.action === 'video.thumbnail.refused');
      assert.ok(row, 'le refus de capacité est journalisé');
      assert.match(JSON.stringify(row.detail ?? row), /VIDEO_TOOLS_DISABLED/);
      assert.ok(!/\/(home|tmp|var|app|Users)\//.test(JSON.stringify(row)), 'aucun chemin serveur dans la ligne du journal');
    });

    it('écrit une vignette, validée, rattachée, et la rend comme un fichier ordinaire', async () => {
      const out = await media.thumbnail({ videoId: asset.id });
      assert.equal(out.format, 'png');
      assert.ok(out.fileId > 0);
      const row = ctx.runtime.db.get(`SELECT * FROM files WHERE id = ?`, [out.fileId]);
      assert.equal(row.parent_file_id, storedFile.id, 'l’artefact est rattaché à sa source');
      assert.equal(row.owner_id, asset.ownerId ?? row.owner_id);
      assert.equal(row.kind, 'image');
      assert.equal(row.mime_type, 'image/png');
      assert.ok(Number(row.size_bytes) <= 64 * 1024, `taille sous le plafond (${row.size_bytes})`);
      const bytes = fs.readFileSync(path.resolve(ctx.dir, 'uploads', row.relative_path));
      assert.ok(isPng(bytes), 'ce qui est stocké est bien un PNG, pas ce que l’outil a vomi');

      const seen = await user.get(`/api/files/${storedFile.id}`);
      assert.ok(seen.body.children.some((c) => c.id === out.fileId), 'le bordereau de la source liste sa vignette');
      const fetched = await user.get(`/api/files/${out.fileId}/content?inline=1`);
      assert.equal(fetched.status, 200);
      assert.equal(fetched.headers.get('content-type'), 'image/png');

      const stats = await user.get('/api/videos/stats');
      assert.equal(stats.body.tools.enabled, true);
      assert.equal(stats.body.tools.binary, true, 'le shim joue le rôle du binaire, et le serveur le dit');
      assert.equal(rowOf(asset.id).status, 'ready', 'le rapport de la vidéo n’a pas été abîmé par le traitement');
    });

    it('jette une sortie qui n’est pas un PNG et journalise le refus', async () => {
      setMode(inputPath(), 'noise');
      try {
        await rejects(() => media.thumbnail({ videoId: asset.id }), (err) => {
          assert.equal(err.status, 422);
          assert.equal(err.code, 'VIDEO_TOOL_OUTPUT_REFUSED');
          return true;
        });
      } finally {
        setMode(inputPath(), null);
      }
      const trail = await admin.get('/api/admin/audit?limit=40');
      const refusal = (trail.body.items ?? []).find((a) => a.action === 'video.thumbnail.refused');
      assert.ok(refusal, 'un refus de sortie est un événement, pas un trou de mémoire');
      assert.ok(!/\/(home|tmp|var|app)\//.test(String(refusal.detail ?? '') + JSON.stringify(refusal)), `le journal ne porte pas le chemin de stockage : ${JSON.stringify(refusal).slice(0, 160)}`);
      const orphans = ctx.runtime.db.get(`SELECT count(*) c FROM files WHERE parent_file_id = ? AND deleted_at IS NULL`, [storedFile.id]).c;
      assert.equal(orphans, 1, 'le rebut n’a pas été stocké : la vignette validée du test précédent reste la seule');
    });

    it('refuse un dépassement de plafond sans rien laisser derrière lui', async () => {
      setMode(inputPath(), 'huge');
      const before = ctx.runtime.db.get(`SELECT count(*) c FROM files`).c;
      try {
        await rejects(() => media.thumbnail({ videoId: asset.id }), (err) => {
          assert.equal(err.code, 'VIDEO_TOOL_OUTPUT_REFUSED');
          return true;
        });
      } finally {
        setMode(inputPath(), null);
      }
      assert.equal(ctx.runtime.db.get(`SELECT count(*) c FROM files`).c, before, 'aucune ligne ajoutée pour une sortie jetée');
      const leftovers = fs.readdirSync(ctx.dir).filter((n) => String(n).startsWith('ps-thumb-'));
      assert.deepEqual(leftovers, [], 'le répertoire de travail est détruit même en cas de refus');
    });

    it('refuse une vidéo en quarantaine, et un fichier dont la taille a bougé', async () => {
      const q = await admin.post(`/api/videos/${asset.id}/quarantine`, { reason: 'test de la porte' });
      assert.equal(q.status, 200);
      await rejects(() => media.thumbnail({ videoId: asset.id }), (err) => {
        assert.equal(err.status, 409);
        assert.equal(err.code, 'VIDEO_NOT_READY');
        return true;
      });
      await admin.post(`/api/videos/${asset.id}/release`, {});

      const abs = inputPath();
      const real = fs.statSync(abs).size;
      fs.appendFileSync(abs, 'x');
      try {
        await rejects(() => media.thumbnail({ videoId: asset.id }), (err) => {
          assert.equal(err.code, 'VIDEO_SIZE_MISMATCH', 'on ne vignette pas un fichier qui n’est plus celui qui a été analysé');
          return true;
        });
      } finally {
        const fd = fs.openSync(abs, 'r+');
        fs.ftruncateSync(fd, real);
        fs.closeSync(fd);
      }
      const ok = await media.thumbnail({ videoId: asset.id });
      assert.ok(ok.fileId, 'la lecture reprend dès que la taille concorde');
    });

    it('ne trouve pas de vidéo inexistante, et n’attribue l’artefact qu’au porteur de la source', async () => {
      const before0 = ctx.runtime.db.get(`SELECT count(*) c FROM files WHERE parent_file_id = ?`, [storedFile.id]).c;
      for (const bogus of [999_999, 'abc', -1, null]) {
        await rejects(() => media.thumbnail({ videoId: bogus }), (err) => {
          assert.equal(err.status, 404, `identifiant ${JSON.stringify(bogus)} → statut ${err.status}`);
          return true;
        });
      }
      assert.equal(ctx.runtime.db.get(`SELECT count(*) c FROM files WHERE parent_file_id = ?`, [storedFile.id]).c, before0, 'aucun octet produit pour une vidéo qui n’existe pas');
      const before = ctx.runtime.db.get(`SELECT count(*) c FROM files WHERE parent_file_id = ?`, [storedFile.id]).c;
      assert.ok(before >= 1);
      const lastFileId = ctx.runtime.db.get(`SELECT id FROM files ORDER BY id DESC LIMIT 1`).id;
      // Le service attache l'artefact au propriétaire de la vidéo, jamais à l'identité qui a posé la demande.
      const out = await media.thumbnail({ videoId: asset.id });
      const row = ctx.runtime.db.get(`SELECT * FROM files WHERE id = ?`, [out.fileId]);
      assert.ok(row.id <= lastFileId, 'l’artefact est une ligne de la table commune (reconnue par empreinte si elle est identique)');
      assert.equal(row.parent_file_id, storedFile.id);
      assert.equal(row.owner_id, asset.ownerId ?? row.owner_id);
      assert.ok(row.owner_id > 0, 'un artefact a un propriétaire, sinon il devient lisible par personne ou par tout le monde');
    });

    it('refuse la portée d’un compte qui n’a pas le droit de voir le média', async () => {
      const otherFile = await uploadVideo(admin, { name: 'autre.mp4', buffer: buildMp4({ durationMs: 1500, mdatSize: 2048, sampleDelta: 7 }) });
      const other = await admin.post('/api/videos', { fileId: otherFile.body.file.id });
      assert.equal(other.status, 201, JSON.stringify(other.body));
      const foreignId = other.body.asset.id;
      // Frontière réelle : un compte ne peut pas poser de tâche sur le média d'un autre.
      const denied = await user.post(`/api/videos/${foreignId}/jobs`, { kind: 'thumbnail' });
      assert.ok(denied.status === 404 || denied.status === 403, `statut ${denied.status} — la portée répond par l'inexistence, pas par un « non » bavard`);
      const queue = await admin.get(`/api/videos/jobs?videoId=${foreignId}`);
      assert.equal((queue.body.items ?? []).length, 0, 'aucune tâche fantôme n’a été créée au passage');
    });

    it('borne les paramètres venus de la tâche, sans leur faire confiance', () => {
      const sane = media.jobInput({ input_json: JSON.stringify({ atMs: 1500, width: 640, format: 'wav', maxSeconds: 30 }) });
      assert.deepEqual(
        { atMs: sane.atMs, width: sane.width, format: sane.format, maxSeconds: sane.maxSeconds },
        { atMs: 1500, width: 640, format: 'wav', maxSeconds: 30 },
      );
      const junk = media.jobInput({ input_json: '{"atMs": "beaucoup", "width": -9, "format": "png; rm -rf /", "maxSeconds": 1e12}' });
      assert.equal(junk.width, 32, 'une valeur folle retombe sur la borne basse');
      assert.equal(junk.format, 'png', 'un format inconnu n’est pas transmis à l’outil');
      assert.ok(junk.maxSeconds <= 3600);
      assert.equal(media.jobInput({ input_json: 'pas-du-json' }).format, 'png', 'une charge illisible retombe sur les réglages, elle ne casse rien');
      assert.throws(() => media.deriveForJob({ video_id: 'abc' }), /vidéo cible/);
    });

    it('expose la piste WAV comme un format de la même tâche, et rien d’autre', async () => {
      setMode(inputPath(), 'wav');
      try {
        const out = await media.deriveForJob({ video_id: asset.id, input_json: JSON.stringify({ format: 'wav', maxSeconds: 5 }) });
        assert.equal(out.format, 'wav');
        const row = ctx.runtime.db.get(`SELECT * FROM files WHERE id = ?`, [out.fileId]);
        assert.equal(row.mime_type, 'audio/wav');
        assert.equal(row.kind, 'audio');
        assert.equal(out.sampleRate, 16_000, 'le résultat dit le profil réellement demandé');
        assert.equal(row.parent_file_id, storedFile.id);
      } finally {
        setMode(inputPath(), null);
      }
      // Une tâche `thumbnail` sans format reste une vignette : le défaut n'est pas une option client.
      const back = await media.deriveForJob({ video_id: asset.id, input_json: null });
      assert.equal(back.format, 'png');
    });
  });

  describe('file d’exécution et API', () => {
    let ctx;
    let admin;
    let asset;
    let storedFile;

    before(async () => {
      ctx = await boot({ extraConfig: { FFMPEG_PATH: shimPath } });
      admin = ctx.client();
      await admin.login(ADMIN.id, ADMIN.password);
      await admin.put('/api/admin/settings', {
        entries: { 'video.enabled': true, 'video.tools_enabled': true, 'video.async_probe': false, 'video.thumbnail_max_kb': 64 },
      });
      const up = await uploadVideo(admin, { name: 'via-file.mp4', buffer: buildMp4({ durationMs: 2200, mdatSize: 3072, sampleDelta: 3 }) });
      assert.equal(up.status, 201, JSON.stringify(up.body));
      storedFile = up.body.file;
      const declared = await admin.post('/api/videos', { fileId: storedFile.id });
      assert.equal(declared.status, 201, JSON.stringify(declared.body));
      asset = declared.body.asset;
    });

    after(async () => {
      await ctx.close();
    });

    it('accepte une tâche de vignette avec ses paramètres, et la liste', async () => {
      const ask = await admin.post(`/api/videos/${asset.id}/jobs`, { kind: 'thumbnail', input: { atMs: 900, width: 480 } });
      assert.equal(ask.status, 202, JSON.stringify(ask.body));
      const job = await admin.get(`/api/videos/jobs/${ask.body.job.id}`);
      assert.equal(job.body.job.kind, 'thumbnail');
      assert.equal(job.body.job.status, 'queued');
      const again = await admin.post(`/api/videos/${asset.id}/jobs`, { kind: 'thumbnail', input: { atMs: 100 } });
      assert.equal(again.body.job.id, ask.body.job.id, 'redemander la même nature de tâche rebornée ne superpose pas deux lignes');
    });

    it('refuse une clé inconnue dans les paramètres de tâche', async () => {
      const sneaky = await admin.post(`/api/videos/${asset.id}/jobs`, { kind: 'thumbnail', input: { format: 'png', ownerId: 999 } });
      assert.equal(sneaky.status, 400, JSON.stringify(sneaky.body));
      assert.match(sneaky.body.error.message, /non autorisé|ownerId/, 'le validateur ferme l’objet, il ne le tamise pas');
      const badFormat = await admin.post(`/api/videos/${asset.id}/jobs`, { kind: 'thumbnail', input: { format: 'exe' } });
      assert.equal(badFormat.status, 400);
      const notObject = await admin.post(`/api/videos/${asset.id}/jobs`, { kind: 'thumbnail', input: 'png' });
      assert.equal(notObject.status, 400, 'un format d’objet attendu, pas une tolérance');
    });

    it('fait tourner la tâche par le runner et garde la trace de l’artefact dans le résultat', async () => {
      // Une redemande refile la même ligne et lui applique SES paramètres : on repose donc la
      // tâche complète ici, sinon ce test dépendrait de l'état laissé par le précédent.
      const reask = await admin.post(`/api/videos/${asset.id}/jobs`, { kind: 'thumbnail', input: { atMs: 900, width: 480 } });
      assert.equal(reask.status, 202, JSON.stringify(reask.body));
      const media = ctx.runtime.videoMedia;
      const runner = createVideoJobRunner({
        service: ctx.runtime.videoJobs,
        videos: ctx.runtime.videos,
        db: ctx.runtime.db,
        workerId: 'outilleur',
        kinds: ['thumbnail'],
        handlers: { thumbnail: async (job) => media.deriveForJob(job) },
      });
      const out = await runner.tick();
      assert.equal(out.claimed.length, 1, JSON.stringify(out));
      assert.equal(out.claimed[0].ok, true, JSON.stringify(out.claimed[0]));
      const list = await admin.get(`/api/videos/jobs?videoId=${asset.id}`);
      const done = list.body.items.find((j) => j.kind === 'thumbnail');
      assert.equal(done.status, 'succeeded');
      assert.equal(done.result.width, 480, 'les paramètres réellement appliqués sont relisibles dans le résultat');
      assert.equal(done.result.maxBytes, 64 * 1024, 'le plafond effectif est celui du réglage, pas une promesse');
      assert.equal(done.result.atMs, 900);
      assert.ok(done.result.fileId > 0);
      const children = await admin.get(`/api/files/${storedFile.id}`);
      assert.ok(children.body.children.some((c) => c.id === done.result.fileId), 'l’artefact est rattaché et visible depuis la source');
    });

    it('marque l’échec nommé quand l’outil disparaît du serveur', async () => {
      const previous = process.env.FFMPEG_PATH;
      process.env.FFMPEG_PATH = 'ffmpeg-absent-de-ce-serveur';
      const media = createVideoMediaService({
        db: ctx.runtime.db,
        config: { ...ctx.runtime.config, video: { ...ctx.runtime.config.video, ffmpegPath: 'ffmpeg-absent-de-ce-serveur' } },
        settings: ctx.runtime.settings,
        files: ctx.runtime.files,
        videos: ctx.runtime.videos,
        audit: ctx.runtime.audit,
        scratchRoot: ctx.dir,
      });
      try {
        await rejects(() => media.thumbnail({ videoId: asset.id }), (err) => {
          assert.equal(err.status, 503);
          assert.equal(err.code, 'VIDEO_TOOL_UNAVAILABLE');
          return true;
        });
      } finally {
        process.env.FFMPEG_PATH = previous;
      }
      assert.equal(media.limits().enabled, true, 'la capacité reste ouverte : c’est l’outil qui manque, et les deux sont distincts');
    });
  });
});
