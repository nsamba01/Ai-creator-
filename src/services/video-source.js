/**
 * Politique unique : « ces octets sont bien ceux qui ont été analysés ».
 *
 * Deux chemins du produit ont besoin de la même réponse — la lecture en continu (qui débite de
 * l'octet) et le traitement hors-bande (qui ouvre le fichier avec un outil externe). Si ces
 * contrôles vivaient deux fois, l'un des deux dériverait : par exemple un worker qui produirait
 * une vignette d'un fichier remplacé sur disque après son analyse, ou qui lirait un média en
 * quarantaine. D'où ce module, importé par les deux.
 *
 * Rien ici ne décide d'une autorisation : la portée (à qui appartient la vidéo) est tranchée en
 * amont par `videos.scopedRow()`, qui sert aussi le rapport JSON.
 */
import fs from 'node:fs';
import { AppError, notFound } from '../utils/errors.js';

export const SOURCE_ERRORS = {
  NOT_READY: 'VIDEO_NOT_READY',
  SIZE_MISMATCH: 'VIDEO_SIZE_MISMATCH',
  UNSAFE_SOURCE: 'VIDEO_UNSAFE_SOURCE',
};

/** Le média n'est ni prêt, ni valide, ni accepté : on refuse avec le motif, pas un 500. */
export function assertReadyForRender(asset) {
  if (asset.status === 'ready') return asset;
  const why =
    asset.status === 'quarantined'
      ? 'Vidéo en quarantaine : aucun octet de média ne sort tant qu’un administrateur ne l’a pas validée.'
      : asset.status === 'failed'
        ? 'Le sondage a échoué : relancez-le avant de lire.'
        : 'Le sondage n’est pas terminé : la lecture n’ouvrira qu’une vidéo déclarée prête.';
  throw new AppError(409, SOURCE_ERRORS.NOT_READY, why, { status: asset.status, errorCode: asset.error_code ?? null });
}

/**
 * Relit le stockage et rend `{ fileRow, abs, size }` uniquement si le fichier sur disque est
 * exactement celui qui a été accepté à l'écriture : type vidéo confirmé par signature, chemin
 * régulier, taille concordant avec `files.size_bytes`.
 *
 * `files.resolveStored` est le seul traducteur `relative_path` → chemin absolu : aucun appelant
 * ne construit un chemin à la main, donc aucun ne peut sortir du dépôt par une valeur lue en base.
 */
export function verifiedSource({ db, files, asset, sizeMustMatch = true }) {
  const fileRow = db.get(`SELECT * FROM files WHERE id = ? AND deleted_at IS NULL`, [asset.file_id]);
  if (!fileRow) throw notFound('Fichier source introuvable.');
  if (fileRow.kind !== 'video' || Number(fileRow.magic_ok) !== 1) {
    throw new AppError(403, SOURCE_ERRORS.UNSAFE_SOURCE, 'Source refusée : le fichier n’a pas été validé comme vidéo.');
  }

  const abs = files.resolveStored(fileRow.relative_path);
  let st = null;
  try {
    st = fs.statSync(abs);
  } catch {
    throw notFound('Fichier absent du stockage.');
  }
  if (!st.isFile()) {
    throw new AppError(403, SOURCE_ERRORS.UNSAFE_SOURCE, 'Source refusée : le chemin de stockage n’est pas un fichier régulier.');
  }
  if (sizeMustMatch && Number(fileRow.size_bytes) !== st.size) {
    throw new AppError(409, SOURCE_ERRORS.SIZE_MISMATCH, 'Taille sur disque différente de celle enregistrée : contenu à revérifier.', {
      expected: Number(fileRow.size_bytes),
      found: st.size,
    });
  }
  return { fileRow, abs, size: st.size };
}

export default { SOURCE_ERRORS, assertReadyForRender, verifiedSource };
