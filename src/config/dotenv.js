/**
 * Lecteur « .env » sans dépendance.
 *
 * Le projet n’installe volontairement aucune dépendance native ni utilitaire :
 * ce petit parseur couvre le besoin réel (charger la configuration locale de
 * développement) sans ajouter de surface d’attaque.
 *
 * Règles volontairement strictes :
 *  - une variable déjà présente dans l’environnement du processus gagne toujours
 *    (les secrets viennent de l’orchestrateur, pas du disque) ;
 *  - aucune valeur n’est journalisée, jamais ;
 *  - le fichier doit être un fichier régulier du dépôt : pas de lien symbolique
 *    pointant ailleurs, pas de chemin absolu (un .env compromis dans un volume
 *    partagé ne doit pas devenir un lecteur de /etc) ;
 *  - les lignes non conformes sont ignorées silencieusement.
 */
import fs from 'node:fs';
import path from 'node:path';

const LINE_RE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/;

export function parseDotenv(text) {
  const out = {};
  for (const rawLine of String(text).split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const m = LINE_RE.exec(line);
    if (!m) continue;
    const key = m[1];
    let value = m[2].trim();
    if ((value.startsWith('"') && value.endsWith('"') && value.length > 1) || (value.startsWith("'") && value.endsWith("'") && value.length > 1)) {
      value = value.slice(1, -1);
    } else {
      // Un commentaire non entre guillemots termine la valeur.
      const hash = value.indexOf(' #');
      if (hash >= 0) value = value.slice(0, hash).trim();
    }
    out[key] = value;
  }
  return out;
}

/**
 * @param {{ root?: string, file?: string, env?: NodeJS.ProcessEnv, allowAbsolute?: boolean }} [options]
 * @returns {{ loaded: string[], skipped: string[], file: string | null, warning?: string }}
 */
export function loadDotenv({ root = process.cwd(), file = '.env', env = process.env, allowAbsolute = false } = {}) {
  const target = path.isAbsolute(file) && allowAbsolute ? file : path.join(root, file);
  const result = { loaded: [], skipped: [], file: null };
  if (!path.isAbsolute(target) || !target.startsWith(path.resolve(root) + path.sep)) {
    result.warning = 'chemin .env hors du projet : ignoré';
    return result;
  }
  let stat;
  try {
    stat = fs.lstatSync(target);
  } catch {
    return result; // aucun fichier : fonctionnement nominal
  }
  if (stat.isSymbolicLink() || !stat.isFile()) {
    result.warning = 'fichier .env inhabituel (lien symbolique ou fichier spécial) : ignoré';
    return result;
  }
  if (stat.size > 64 * 1024) {
    result.warning = 'fichier .env anormalement volumineux : ignoré';
    return result;
  }

  let parsed;
  try {
    parsed = parseDotenv(fs.readFileSync(target, 'utf8'));
  } catch {
    result.warning = 'lecture .env impossible : ignoré';
    return result;
  }
  result.file = target;
  for (const [key, value] of Object.entries(parsed)) {
    if (env[key] !== undefined && env[key] !== '') {
      result.skipped.push(key);
      continue;
    }
    env[key] = value;
    result.loaded.push(key);
  }
  return result;
}

export default loadDotenv;
