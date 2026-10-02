/**
 * Exécution d'un outil média externe (ffmpeg) — phase C de l'agent vidéo.
 *
 * Un décodeur est le plus vieux vecteur du métier : on lui donne un fichier que quelqu'un d'autre
 * a écrit. Ce module existe pour que la surface d'attaque tienne dans trois phrases :
 *  1. aucun shell — le fils est lancé par une liste d'arguments (`spawnSync` puis tableau), jamais par une chaîne ;
 *  2. aucun mot venant du client dans `argv` — ni le nom téléversé, ni l'URL, ni le motif :
 *     seulement deux chemins internes (source, sortie) et des entiers bornés ;
 *  3. tout est borné — délai dur avec `SIGKILL`, volume de sortie, taille de sortie, et le
 *     binaire doit être résolu par `safeBinaryPath` (nom simple ou absolu, exécutable réel).
 *
 * Le traitement n'a rien à faire dans le processus web : cet appelant est le worker
 * (`scripts/video-worker.js`), isolé réseau coupé.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
// lint-allow: ce module est le seul endroit du produit qui exécute un binaire externe ;
// les quatre règles au-dessus (pas de shell, argv figé, environnement vidé, délai dur) s'y appliquent.
import { spawnSync } from 'node:child_process';
import { AppError } from '../utils/errors.js';
import { safeMessage } from '../utils/sanitize.js';

export const TOOL_ERRORS = {
  DISABLED: 'VIDEO_TOOLS_DISABLED',
  UNAVAILABLE: 'VIDEO_TOOL_UNAVAILABLE',
  FAILED: 'VIDEO_TOOL_FAILED',
  OUTPUT_REFUSED: 'VIDEO_TOOL_OUTPUT_REFUSED',
};

/** Signature PNG : ce qu'on attend d'une vignette, vérifiée avant tout stockage. */
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

function clamp(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

/**
 * Ligne de commande d'une vignette : une image, à une position bornée, redimensionnée, sans son,
 * sans sous-titre, sans données. Les valeurs sont des entiers clamps ; le nom du fichier original
 * n'apparait nulle part (la sortie est un chemin de travail interne).
 */
export function thumbnailArgs({ abs, out, atMs = 1000, width = 320 } = {}) {
  if (!abs || !out) throw new AppError(500, 'VIDEO_TOOL_FAILED', 'Arguments de vignette incomplets.');
  const seconds = (clamp(atMs, 0, 86_400_000, 1000) / 1000).toFixed(3);
  const w = clamp(width, 32, 1920, 320);
  return [
    '-hide_banner',
    '-loglevel', 'error',
    '-nosplit',
    '-nostdin',
    '-y',
    '-ss', seconds,
    '-i', String(abs),
    '-frames:v', '1',
    '-an', '-sn', '-dn',
    '-vf', `scale=${w}:-2:flags=area`,
    '-f', 'image2',
    '-update', '1',
    String(out),
  ];
}

/**
 * Profil de la piste extraite. Une seule définition : ce que l'outil reçoit et ce que le rapport
 * affiche sortent du même objet, donc un résultat ne peut pas promettre 48 kHz pendant que l'outil
 * tourne à 16.
 */
export const AUDIO_PROFILE = Object.freeze({ sampleRate: 16_000, channels: 1 });

/**
 * Extraction d'une piste audio brute (PCM 16 kHz mono) pour une transcription locale ultérieure :
 * même discipline, et un plafond de durée pour qu'un fichier d'une heure ne sature pas le disque.
 */
export function audioArgs({ abs, out, maxSeconds = 300, sampleRate = AUDIO_PROFILE.sampleRate, channels = AUDIO_PROFILE.channels } = {}) {
  if (!abs || !out) throw new AppError(500, 'VIDEO_TOOL_FAILED', 'Arguments audio incomplets.');
  return [
    '-hide_banner',
    '-loglevel', 'error',
    '-nosplit',
    '-nostdin',
    '-y',
    '-i', String(abs),
    '-vn', '-sn', '-dn',
    '-t', String(clamp(maxSeconds, 1, 3600, 300)),
    '-acodec', 'pcm_s16le',
    '-ar', String(clamp(sampleRate, 8000, 48000, 16000)),
    '-ac', String(clamp(channels, 1, 2, 1)),
    '-f', 'wav',
    String(out),
  ];
}

/** Vrai si le fichier commence par la signature PNG attendue. */
export function isPng(buffer) {
  return Buffer.compare(buffer.subarray(0, 8), PNG_SIGNATURE) === 0;
}

/**
 * Répertoire de travail jetable, hors du dépôt de fichiers servis, en 0700 : l'outil n'écrit que
 * là, et le fichier n'entre dans le stockage définitif qu'après validation (taille et signature).
 */
export function makeScratch({ root = os.tmpdir(), label = 'ps-video' } = {}) {
  const base = path.resolve(root);
  const dir = path.join(base, `${label}-${process.pid}-${crypto.randomBytes(4).toString('hex')}`);
  if (!dir.startsWith(base + path.sep)) throw new AppError(500, 'VIDEO_TOOL_FAILED', 'Répertoire de travail refusé.');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  return {
    dir,
    file(name) {
      const abs = path.join(dir, String(name).replace(/[^\w.\-]/g, '_'));
      if (!abs.startsWith(dir + path.sep)) throw new AppError(500, 'VIDEO_TOOL_FAILED', 'Chemin de sortie refusé.');
      return abs;
    },
    dispose() {
      try {
        fs.rmSync(dir, { recursive: true, force: true });
      } catch {
        /* un répertoire qui résiste à la purge n'est pas une raison d'échouer la tâche */
      }
    },
  };
}

/**
 * Lanceur. `run({ bin, args, outPath, maxOutBytes })` renvoie un résultat **jamais** une exception :
 * l'appelant décide du code d'erreur, et n'a pas à connaître les subtilités de `spawnSync`.
 *
 * `timeoutMs` est borné (1 s … 5 min) : un administrateur peut le baisser, pas le régler à 24 heures.
 */
export function createFfmpegRunner({ timeoutMs = 30_000, maxBufferBytes = 2 * 1024 * 1024 } = {}) {
  const timeout = clamp(timeoutMs, 1000, 300_000, 30_000);
  const maxBuffer = clamp(maxBufferBytes, 16_384, 16 * 1024 * 1024, 2 * 1024 * 1024);

  function run({ bin, args, outPath, maxOutBytes = 512 * 1024 }) {
    if (typeof bin !== 'string' || !bin) return { ok: false, code: TOOL_ERRORS.UNAVAILABLE, reason: 'binaire non résolu' };
    if (!Array.isArray(args) || args.length === 0 || args.some((a) => typeof a !== 'string' || !a.length || a.includes('\0'))) {
      return { ok: false, code: TOOL_ERRORS.FAILED, reason: 'arguments refusés' };
    }
    const cap = clamp(maxOutBytes, 4096, 64 * 1024 * 1024, 512 * 1024);
    // lint-allow: pas de shell ; argv construit ici ; environnement réduit ; délai dur ; sortie bornée.
    const res = spawnSync(bin, args, {
      encoding: 'buffer',
      timeout,
      killSignal: 'SIGKILL',
      maxBuffer,
      env: { PATH: '/usr/local/bin:/usr/bin:/bin' },
      cwd: path.dirname(String(outPath ?? process.cwd())),
    });
    if (res.error) {
      const code = res.error.code === 'ENOENT' ? TOOL_ERRORS.UNAVAILABLE : TOOL_ERRORS.FAILED;
      const reason = res.error.code === 'ETIMEDOUT' ? `délai dépassé (${timeout} ms), processus tué` : safeMessage(res.error);
      return { ok: false, code, reason };
    }
    if (res.status === null) {
      return { ok: false, code: TOOL_ERRORS.FAILED, reason: `outil interrompu (signal ${res.signal ?? 'inconnu'}) — délai de ${timeout} ms` };
    }
    if (res.status !== 0) {
      return { ok: false, code: TOOL_ERRORS.FAILED, reason: `l’outil a répondu ${res.status}`, detail: safeMessage(stderrText(res.stderr)) };
    }
    let st = null;
    try {
      st = fs.statSync(outPath);
    } catch {
      return { ok: false, code: TOOL_ERRORS.OUTPUT_REFUSED, reason: 'aucune sortie produite' };
    }
    if (!st.isFile()) return { ok: false, code: TOOL_ERRORS.OUTPUT_REFUSED, reason: 'sortie non régulière' };
    if (st.size === 0) return { ok: false, code: TOOL_ERRORS.OUTPUT_REFUSED, reason: 'sortie vide' };
    if (st.size > cap) {
      try {
        fs.unlinkSync(outPath);
      } catch {
        /* mieux vaut un résidu dans un répertoire 0700 qu'une tâche qui échoue deux fois */
      }
      return { ok: false, code: TOOL_ERRORS.OUTPUT_REFUSED, reason: `sortie refusée : ${st.size} octets pour un plafond de ${cap}` };
    }
    const buffer = fs.readFileSync(outPath);
    if (buffer.length > cap) return { ok: false, code: TOOL_ERRORS.OUTPUT_REFUSED, reason: 'sortie trop volumineuse' };
    return { ok: true, buffer, bytes: buffer.length, note: stderrText(res.stderr) ? safeMessage(stderrText(res.stderr)) : null };
  }

  return { run, timeout, maxBuffer };
}

function stderrText(buf) {
  if (!buf) return '';
  const text = Buffer.isBuffer(buf) ? buf.toString('utf8') : String(buf);
  // ffmpeg écrit beaucoup sur stderr quand il travaille bien : on ne garde que la fin, bornée.
  return text.slice(-800);
}

export default { TOOL_ERRORS, thumbnailArgs, audioArgs, isPng, makeScratch, createFfmpegRunner };
