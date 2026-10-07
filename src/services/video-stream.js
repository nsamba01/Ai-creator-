/**
 * Lecture en continu d'une vidéo (phase B).
 *
 * Ce module ne fait PAS de la magie média : il rend un octet-stream **borné**, pour un
 * fichier dont on a vérifié trois choses — qu'il est à l'utilisateur qui demande (ou à un
 * compte autorisé), que son conteneur a été validé à l'écriture, et que le rapport de sondage
 * le déclare `ready`. Un fichier en quarantaine ne reçoit personne.
 *
 * Points de robustesse qui sont ici pour une raison précise :
 *  - `Range` est découpé à la main : un `start > end`, un dépassement de taille ou un `suffix`
 *    aberrant doivent produire un `416` propre, pas une plage négative envoyée à `fs`.
 *  - la taille relue sur disque est comparée à celle de la base : un fichier modifié après
 *    coup n'est pas servi comme s'il était intact ;
 *  - le type d'objet est déduit du **conteneur sondé**, pas du nom fourni par le client ;
 *  - `Content-Disposition: inline` avec un nom assaini (ni CRLF, ni guillemet : un en-tête
 *    injecté depuis un nom de fichier serait une faille de réponse).
 */
import fs from 'node:fs';
import { AppError, notFound } from '../utils/errors.js';
import { assertReadyForRender, verifiedSource } from './video-source.js';

// Les codes de refus de la source vivent dans `video-source.js` (lus par le flux et par le
// traitement hors-bande) ; `DISABLED` est propre à cette route et n'a pas d'équivalent ailleurs.
export const STREAM_ERRORS = {
  DISABLED: 'VIDEO_STREAM_DISABLED',
  NOT_READY: 'VIDEO_NOT_READY',
  SIZE_MISMATCH: 'VIDEO_SIZE_MISMATCH',
  UNSAFE_SOURCE: 'VIDEO_UNSAFE_SOURCE',
};

// Clé = famille de conteneur retenue par l’analyse (`video_assets.container`), pas l’extension ni
// le type déclaré à l’envoi : un AVI envoyé avec `Content-Type: video/mp4` doit rester annoncé
// `video/x-msvideo`, sinon le lecteur promet un décodage que le fichier ne tiendra pas.
const CONTAINER_MIME = {
  mp4: 'video/mp4',
  mov: 'video/quicktime',
  webm: 'video/webm',
  mkv: 'video/x-matroska',
  avi: 'video/x-msvideo',
  ogv: 'video/ogg',
};
const ALLOWED_MIME = new Set(['video/mp4', 'video/webm', 'video/ogg', 'video/quicktime', 'video/x-msvideo', 'video/x-m4v']);

/**
 * Parse une seule plage `bytes=`. `null` = pas de plage exploitable (réponse complète,
 * conformément à RFC 7233 qui autorise à ignorer `Range`).
 *
 * @returns {{mode:'full'|'range'|'unsatisfiable', start?:number, end?:number}}
 */
export function parseByteRange(header, size) {
  const raw = String(header ?? '').trim();
  if (!raw || !/^bytes=/i.test(raw)) return { mode: 'full' };
  const spec = raw.slice(6).trim();
  if (!spec || spec.includes(',')) return { mode: 'full' }; // plages multiples : non supportées, on sert tout
  const m = /^(\d*)-(\d*)$/.exec(spec);
  if (!m) return { mode: 'full' };
  const [, s, e] = m;
  if (!s && !e) return { mode: 'full' };
  if (!s) {
    const n = Number(e);
    if (!Number.isFinite(n) || n <= 0) return { mode: 'unsatisfiable' };
    const len = Math.min(Math.trunc(n), Math.max(0, size));
    if (len === 0) return { mode: 'unsatisfiable' };
    return { mode: 'range', start: Math.max(0, size - len), end: Math.max(0, size - 1) };
  }
  const start = Number(s);
  if (!Number.isFinite(start) || start < 0 || start >= size) return { mode: 'unsatisfiable' };
  const end = e === '' ? size - 1 : Number(e);
  if (!Number.isFinite(end) || end < start) return { mode: 'unsatisfiable' };
  return { mode: 'range', start: Math.trunc(start), end: Math.min(Math.trunc(end), size - 1) };
}

/** Nom de fichier sûr pour un en-tête `Content-Disposition`. */
export function safeDispositionName(name) {
  const base = String(name ?? 'video')
    .replace(/[\r\n"\\]/g, '')
    .replace(/[^\p{L}\p{N}._\- ]+/gu, '-')
    .trim()
    .slice(0, 120);
  return base || 'video';
}

export function createVideoStream({ db, files, videos, settings = null } = {}) {
  const enabled = () => {
    const v = settings?.bool?.('video.stream_enabled');
    return v === null || v === undefined ? false : Boolean(v);
  };

  /**
   * Calcule ce qui doit être écrit. Ne lit jamais plus que la plage demandée.
   *
   * @param {{id:number, actor:object, scopeAll?:boolean, rangeHeader?:string, ifNoneMatch?:string, method?:string}} q
   */
  function target({ id, actor, scopeAll = false, rangeHeader = null, ifNoneMatch = null }) {
    if (!Number.isInteger(id) || id <= 0) throw notFound('Vidéo introuvable.');
    if (!enabled()) {
      throw new AppError(409, STREAM_ERRORS.DISABLED, 'La lecture en continu est désactivée : activez le réglage video.stream_enabled.');
    }
    videos?.assertEnabled?.();

    // Portée, état du rapport, puis octets vérifiés : trois appels, aucune règle écrite deux fois.
    const asset = videos.scopedRow({ id, actor, scopeAll });
    assertReadyForRender(asset);
    const { fileRow, abs, size } = verifiedSource({ db, files, asset });

    const mime = CONTAINER_MIME[asset.container] ?? (ALLOWED_MIME.has(fileRow.mime_type) ? fileRow.mime_type : 'video/mp4');
    const etag = `W/"${String(asset.sha256 ?? 'x').slice(0, 16)}-${size}"`;
    const ifMatch = String(ifNoneMatch ?? '').replace(/^W\//, '').trim();
    const notModified = ifMatch && (ifMatch === etag.replace(/^W\//, '') || ifMatch === '*');
    const range = parseByteRange(rangeHeader, size);
    const length = range.mode === 'range' ? range.end - range.start + 1 : size;

    return {
      abs,
      size,
      mime,
      etag,
      status: range.mode === 'range' ? 206 : 200,
      start: range.mode === 'range' ? range.start : 0,
      end: range.mode === 'range' ? range.end : size - 1,
      length,
      contentRange: range.mode === 'range' ? `bytes ${range.start}-${range.end}/${size}` : null,
      unsatisfiable: range.mode === 'unsatisfiable',
      notModified: Boolean(notModified),
      headers: {
        'Accept-Ranges': 'bytes',
        'Content-Type': mime,
        'Content-Length': String(range.mode === 'unsatisfiable' ? 0 : length),
        'Cache-Control': 'private, max-age=0, must-revalidate',
        Vary: 'Cookie, Range',
        ETag: etag,
        'Content-Disposition': `inline; filename="${safeDispositionName(fileRow.original_name)}"`,
        'X-Content-Type-Options': 'nosniff',
        'Cross-Origin-Resource-Policy': 'same-origin',
        'Content-Security-Policy': "default-src 'none'",
      },
      assetId: asset.id,
      fileId: fileRow.id,
    };
  }

  return { target, enabled, STREAM_ERRORS, CONTAINER_MIME, ALLOWED_MIME };
}
