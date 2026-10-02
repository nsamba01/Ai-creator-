#!/usr/bin/env node
/**
 * Worker de l'agent vidéo — processus séparé.
 *
 * Un média se traite hors du serveur web : `ffprobe`/`ffmpeg` sont gourmands et historiquement
 * attaquables par fichier malformé. Ce script est donc lancé par un autre service (voir
 * `docker-compose.yml`, `worker:`) ou par `npm run worker`, avec sa propre connexion à la base
 * (SQLite en mode WAL, `busy_timeout` au démarrage).
 *
 * Le worker ne fait que ce que la file lui donne : réclamer un job (claim sous bail), exécuter,
 * écrire le résultat, prolonger le bail pendant le travail. S'il meurt, le ramassage remet la
 * tâche en file — c'est testé, pas espéré.
 */
import process from 'node:process';
import { loadConfig } from '../src/config/env.js';
import { loadDotenv } from '../src/config/dotenv.js';
import { createRuntime } from '../src/runtime.js';
import { createVideoJobRunner } from '../src/services/video-jobs.service.js';
import { safeBinaryPath } from '../src/services/video.service.js';

loadDotenv({ root: process.cwd() });
const config = loadConfig();
const runtime = createRuntime({ config });
const { videos, videoJobs, db, audit } = runtime;

const workerId = `worker-${process.pid}-${Math.random().toString(36).slice(2, 8)}`;
const kinds = config.video?.workerKinds?.length ? config.video.workerKinds : ['probe'];

const handlers = {
  probe: async (job) => {
    const out = videos.probeForJob({ videoId: job.video_id });
    return {
      videoId: job.video_id,
      status: out.asset.status,
      container: out.asset.container ?? null,
      durationMs: out.asset.durationMs ?? null,
      width: out.asset.width ?? null,
      height: out.asset.height ?? null,
      probeSource: out.asset.probeSource ?? 'none',
      errorCode: out.asset.errorCode ?? null,
    };
  },
  // Les kinds lourds arrivent avec le bac à sable (phases C-D). Ils ne sont pas « oubliés » :
  // ils échouent nommément, ce qui les remet en file puis les marque en échec — la file reste
  // honnête sur ce qu'elle sait faire.
  transcode: async () => {
    throw Object.assign(new Error('le transcodage demande le conteneur worker isolé (phase C)'), { code: 'VIDEO_TOOL_UNAVAILABLE', status: 503 });
  },
  transcribe: async () => {
    throw Object.assign(new Error('la transcription demande un modèle ASR local (phase C)'), { code: 'VIDEO_TOOL_UNAVAILABLE', status: 503 });
  },
  thumbnail: async () => {
    throw Object.assign(new Error('les vignettes demandent ffmpeg (phase C)'), { code: 'VIDEO_TOOL_UNAVAILABLE', status: 503 });
  },
};

if (safeBinaryPath(process.env.FFPROBE_PATH ?? 'ffprobe')) {
  process.stdout.write('ffprobe détecté : le sondage l’utilisera en complément de l’en-tête\n');
} else {
  process.stdout.write('ffprobe absent : sondage sur en-têtes uniquement (aucune valeur inventée)\n');
}

const runner = createVideoJobRunner({ service: videoJobs, videos, db, workerId, handlers, kinds });

// La boucle du runner est volontairement non bloquante (timer `unref`) : sans cet
// intervalle de service, un worker au repos s'éteindrait sans qu'on le lui ait demandé.
const keepAlive = setInterval(() => {}, 1 << 15);

let stopping = false;
const stop = (signal) => {
  if (stopping) return;
  stopping = true;
  runner.stop();
  clearInterval(keepAlive);
  process.stdout.write(`arrêt du worker (${signal}) : le job en cours finit ou expire son bail\n`);
  setTimeout(() => process.exit(0), 250).unref();
};
process.on('SIGTERM', () => stop('SIGTERM'));
process.on('SIGINT', () => stop('SIGINT'));

process.stdout.write(`worker vidéo démarré ${JSON.stringify({ workerId, kinds, pollMs: config.video?.workerPollMs ?? 1000, leaseSeconds: videoJobs.limits().leaseMs / 1000, maxAttempts: videoJobs.limits().maxAttempts })}\n`);

if (process.argv.includes('--once')) {
  // Un seul tour de boucle puis sortie : mode cron, et mode « est-ce que ma file avance ? »
  // sans laisser un processus derrière soi.
  const out = await runner.tick();
  process.stdout.write(`tick : ${JSON.stringify({ reaped: out.reaped, claimed: out.claimed.map((c) => ({ id: c.id, kind: c.kind, ok: c.ok, errorCode: c.errorCode ?? null })), idle: out.idle })}\n`);
  runner.stop();
  process.exit(0);
}

runner.start({
  pollMs: config.video?.workerPollMs ?? 1000,
  onTick: (out) => {
    if (out?.error) process.stderr.write(`erreur de boucle : ${out.error}\n`);
    if (out?.reaped?.examined) audit?.record?.({ action: 'video.job.reaped', category: 'agents', outcome: 'success', severity: 'notice', detail: out.reaped });
  },
});

// Aucune interface HTTP n'est exposée ici : le worker ne parle qu'à la base.
