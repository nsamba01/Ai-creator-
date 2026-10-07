/**
 * Politique unique de nettoyage d'un message technique avant qu'il ne soit stocké ou renvoyé.
 *
 * Deux appelants partagent cette fonction — la file d'exécution (message d'échec d'un job) et le
 * lanceur d'outils médias (sortie stderr de ffmpeg/ffprobe). C'est délibéré : si la neutralisation
 * des chemins vivait à deux endroits, l'un des deux dériverait et un chemin de stockage remonterait
 * un jour jusqu'à un client. Un message d'erreur n'est jamais qu'un libellé : il ne doit rien révéler
 * de la topologie du serveur.
 */
import { redact } from './logger.js';

/** Chemins absolus POSIX, URLs `file://`, lecteurs Windows, puis secrets connus. */
export function scrubPaths(text) {
  return String(text ?? '')
    .replace(/[\u0000-\u0008]/g, ' ')
    .replace(/(?:file:\/\/)?(?:\/[\w.\-]+)+/g, '[chemin masqué]')
    .replace(/[A-Za-z]:\\(?:[\w.\\-]+)+/g, '[chemin masqué]')
}

/**
 * Message court, sans chemin, sans secret, sans retours à la ligne : ce qui est écrit dans
 * `video_jobs.error_message`, dans un journal, ou dans une réponse d'erreur.
 */
export function safeMessage(err, { max = 300 } = {}) {
  const raw = typeof err === 'string' ? err : String(err?.message ?? err ?? 'erreur inconnue');
  const stripped = redact(scrubPaths(raw)).replace(/\s+/g, ' ').trim();
  return stripped.slice(0, max) || 'erreur non nommée';
}

export default safeMessage;
