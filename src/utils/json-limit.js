/**
 * JSON borné en taille, **toujours valide**.
 *
 * Les colonnes de rapport (`video_assets.meta_json`, `video_analyses.result_json`) portent une
 * borne de longueur : découper la chaîne produite y écrirait du JSON illisible, que le lecteur
 * rejetterait plus tard en silence — la perte deviendrait invisible. On réduit donc l'objet, pas
 * le texte : tableaux raccourcis, longues chaînes tronquées, puis un marqueur honnête qui
 * déclare la perte.
 */

/**
 * Couper les tableaux de moitié, **tous ceux d’une même passe** : un rapport à mille pistes doit
 * converger en une dizaine d’allers-retours, pas en mille.
 */
function halveArrays(value, depth = 0) {
  if (Array.isArray(value)) {
    const kept = value.slice(0, Math.ceil(value.length / 2));
    return { value: kept.map((v) => halveDeep(v, depth + 1)), changed: value.length > 1 };
  }
  if (value && typeof value === 'object' && depth < 4) {
    let changed = false;
    const next = { ...value };
    for (const key of Object.keys(next)) {
      if (Array.isArray(next[key]) && next[key].length > 1) {
        next[key] = next[key].slice(0, Math.ceil(next[key].length / 2));
        changed = true;
      } else if (next[key] && typeof next[key] === 'object') {
        const inner = halveArrays(next[key], depth + 1);
        if (inner.changed) {
          next[key] = inner.value;
          changed = true;
        }
      }
    }
    if (changed) next.truncated = true;
    return { value: next, changed };
  }
  return { value, changed: false };
}

function halveDeep(value, depth) {
  return halveArrays(value, depth).value;
}

function shrinkStrings(value, width) {
  if (typeof value === 'string') return value.length > width ? `${value.slice(0, Math.max(1, width - 1))}…` : value;
  if (Array.isArray(value)) return value.map((v) => shrinkStrings(v, width));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = shrinkStrings(v, width);
    return out;
  }
  return value;
}

/** @returns {string} un JSON de `limit` caractères au plus, qui se relit toujours. */
export function boundedJson(value, limit = 16_000) {
  const max = Number.isInteger(limit) && limit > 96 ? limit : 16_000; // le plancher fait 73 caractères
  let candidate = value;
  let width = 600;
  for (let round = 0; round < 40; round += 1) {
    const json = JSON.stringify(candidate);
    if (json.length <= max) return json;
    const arrays = halveArrays(candidate);
    if (arrays.changed) {
      candidate = arrays.value;
      continue;
    }
    if (typeof candidate === 'string' && candidate.length > width + 1) {
      candidate = shrinkStrings(candidate, width);
      width = Math.max(6, Math.floor(width / 2));
      continue;
    }
    candidate = shrinkStrings(candidate, width);
    width = Math.max(6, Math.floor(width / 2));
  }
  // Le plancher est choisi pour rester valide quelle que soit la borne : 65 caractères.
  return '{"truncated":true,"note":"rapport irreductible sous la borne de taille"}';
}

export default boundedJson;
