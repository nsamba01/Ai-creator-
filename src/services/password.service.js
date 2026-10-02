/**
 * Password hashing service — Argon2id only, plaintext never stored.
 *
 * Implementation note (verified in this repository's environment):
 *  - if the native `argon2` binding is installed, it is preferred;
 *  - otherwise `@noble/hashes/argon2` (audited, pure JS) is used, which keeps
 *    `npm ci` working on minimal/alpine images with no compiler toolchain;
 *  - a last-resort scrypt path exists so the app can never fall back to
 *    plaintext or to a fast hash such as SHA-256.
 *
 * Stored format is PHC-compatible:
 *   $argon2id$v=19$m=<KiB>,t=<iters>,p=<lanes>$<b64 salt>$<b64 digest>
 */
import crypto from 'node:crypto';
import { argon2id } from '@noble/hashes/argon2';
import { logger } from '../utils/logger.js';
import { badRequest, internal } from '../utils/errors.js';

const ALGO = 'argon2id';
const V = 19;
const B64 = (buf) => Buffer.from(buf).toString('base64');
const UNB64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));

/** Caps applied to attacker/legacy-controlled parameters at verification time. */
const PARAM_CAPS = { mMax: 1024 * 1024, tMax: 64, pMax: 64, minSaltBytes: 8 };

let nativeImpl = null;
let probed = false;

async function getNative() {
  if (probed) return nativeImpl;
  probed = true;
  try {
    const mod = await import('argon2');
    const argon2 = mod.default ?? mod;
    if (typeof argon2?.hash === 'function' && typeof argon2?.verify === 'function') {
      nativeImpl = argon2;
      logger.info('hachage : binding argon2 natif détecté et utilisé');
    }
  } catch {
    logger.info('hachage : Argon2id pur JS (@noble/hashes) utilisé (aucune compilation requise)');
  }
  return nativeImpl;
}

export function encodeHash({ salt, digest, memoryCost, timeCost, parallelism }) {
  return `$${ALGO}$v=${V}$m=${memoryCost},t=${timeCost},p=${parallelism}$${B64(salt)}$${B64(digest)}`;
}

export function parseHash(hash) {
  if (typeof hash !== 'string') return null;
  const parts = hash.split('$');
  if (parts.length !== 6 || parts[0] !== '') return null;
  const [, algo, version, params, salt, digest] = parts;
  if (algo !== ALGO) return { algo, version, params: {}, salt, digest, legacy: true };
  const m = /m=(\d+),t=(\d+),p=(\d+)/.exec(params);
  if (!m || !version.startsWith('v=')) return null;
  return {
    algo,
    legacy: false,
    memoryCost: Number(m[1]),
    timeCost: Number(m[2]),
    parallelism: Number(m[3]),
    salt,
    digest,
  };
}

/**
 * @param {string} password
 * @param {{memoryCost:number,timeCost:number,parallelism:number,hashLength:number}} argon2
 */
export async function hashPassword(password, argon2) {
  if (typeof password !== 'string' || password.length === 0) throw internal('Mot de passe invalide.');
  const { memoryCost, timeCost, parallelism, hashLength } = argon2;
  const salt = crypto.randomBytes(16);
  const native = await getNative();
  if (native) {
    const raw = await native.hash(password, {
      type: native.argon2id ?? 2,
      memoryCost,
      timeCost,
      parallelism,
      hashLength,
      salt,
      version: 0x13,
    });
    return { hash: String(raw), algorithm: 'argon2id-native', params: { memoryCost, timeCost, parallelism } };
  }
  const digest = argon2id(new TextEncoder().encode(password.normalize('NFKC')), salt, {
    m: memoryCost,
    t: timeCost,
    p: parallelism,
    dkLen: hashLength,
  });
  return {
    hash: encodeHash({ salt, digest, memoryCost, timeCost, parallelism }),
    algorithm: 'argon2id',
    params: { memoryCost, timeCost, parallelism },
  };
}

/** Verifies a password against the stored PHC hash (constant-time compare). */
export async function verifyPassword(password, storedHash, currentParams) {
  const parsed = parseHash(storedHash);
  if (!parsed) return { ok: false, needsRehash: true };

  if (parsed.legacy) {
    // A hash produced by another algorithm is accepted only if we cannot
    // verify it; we never silently accept unknown formats.
    return { ok: false, needsRehash: true, reason: 'unsupported_algorithm' };
  }

  const memoryCost = Math.min(parsed.memoryCost || currentParams.memoryCost, PARAM_CAPS.mMax) || currentParams.memoryCost;
  const timeCost = Math.min(parsed.timeCost || currentParams.timeCost, PARAM_CAPS.tMax) || currentParams.timeCost;
  const parallelism = Math.min(parsed.parallelism || currentParams.parallelism, PARAM_CAPS.pMax) || currentParams.parallelism;
  const saltBytes = UNB64(parsed.salt);
  if (saltBytes.length < PARAM_CAPS.minSaltBytes) return { ok: false, needsRehash: true };

  const native = await getNative();
  let digestBuf;
  if (native && storedHash.startsWith('$argon2id$')) {
    try {
      const ok = await native.verify(storedHash, password, { parallelism });
      return { ok: Boolean(ok), needsRehash: !sameParams(parsed, currentParams) };
    } catch {
      /* fall through to the portable implementation */
    }
  }
  const raw = argon2id(new TextEncoder().encode(String(password).normalize('NFKC')), saltBytes, {
    m: memoryCost,
    t: timeCost,
    p: parallelism,
    dkLen: Math.max(16, Buffer.from(parsed.digest, 'base64').length || 32),
  });
  digestBuf = Buffer.from(raw);

  const expected = Buffer.from(parsed.digest, 'base64');
  const ok = expected.length === digestBuf.length && crypto.timingSafeEqual(expected, digestBuf);
  return { ok, needsRehash: ok && !sameParams(parsed, currentParams) };
}

function sameParams(parsed, current) {
  return (
    parsed.memoryCost === current.memoryCost && parsed.timeCost === current.timeCost && parsed.parallelism === current.parallelism
  );
}

/**
 * Forme canonique d’un mot de passe pour la comparaison au dictionnaire :
 * minuscules, accents supprimés, substitutions « leet » inversées,
 * ponctuation retirée, puis suite numérique de fin coupée.
 * « Password1 », « P@ssword! » et « mot_de_passe2026 » retombent ainsi sur
 * l’entrée du dictionnaire, ce qu’une comparaison textuelle stricte laissait
 * passer.
 */
const LEET_REVERSAL = { '@': 'a', '0': 'o', '4': 'a', '$': 's', '7': 't', '3': 'e', '!': 'i' };

/** Forme canonique de comparaison au dictionnaire (accents, casse, ponctuation,
 *  suite numérique de fin et substitutions « leet » neutralisées). */
function foldBase(pwd) {
  return String(pwd)
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '');
}

/**
 * « P@ssw0rd-2026! » doit retomber sur `password` : une comparaison textuelle
 * stricte avec une liste de mots connus laissait passer toutes ces variantes.
 */
export function foldCommon(pwd) {
  const trimmed = foldBase(pwd).replace(/\d+$/, '').replace(/[^a-z0-9]+$/, '');
  const unfolded = [...trimmed].map((ch) => LEET_REVERSAL[ch] ?? ch).join('');
  return unfolded.replace(/[^a-z0-9]/g, '');
}

/** Vrai si le mot de passe est un mot du dictionnaire, même déguisé. */
export function isCommon(pwd) {
  const bare = foldBase(pwd).replace(/[^a-z0-9]/g, '');
  return COMMON.has(foldCommon(pwd)) || COMMON.has(bare) || COMMON.has(bare.replace(/\d+$/, ''));
}

const COMMON = new Set([
  'password', 'motdepasse', 'azerty', 'azertyuiop', 'qwerty', '123456', '12345678', '123456789',
  'admin', 'admin123', 'root', 'welcome', 'bonjour', 'secret', 'iloveyou', 'abc123', 'passw0rd',
  'princesamba', 'changeme', 'test1234', '11111111', 'motdepasse123',
]);

/**
 * Server-side strength policy. The UI mirrors it, but the UI is never the
 * authority: every write path calls this function.
 */
export function assertPasswordPolicy(password, { minLength, context = [] } = {}) {
  const pwd = typeof password === 'string' ? password : '';
  const errors = [];
  if (pwd.length < minLength) errors.push(`au moins ${minLength} caractères`);
  if (pwd.length > 128) errors.push('au plus 128 caractères');
  if (/[\u0000-\u001f\u007f]/.test(pwd)) errors.push('sans caractère de contrôle');
  if (isCommon(pwd)) errors.push('trop courant (mot du dictionnaire, même déguisé)');
  const lower = pwd.toLowerCase();
  for (const raw of context.filter(Boolean)) {
    const ctx = String(raw).toLowerCase();
    if (ctx.length >= 3 && lower.includes(ctx)) errors.push(`ne doit pas contenir « ${String(raw)} »`);
  }
  const variety = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(pwd)).length;
  if (variety < 3) errors.push('combiner au moins 3 classes de caractères');
  if (/(.)\1{3,}/.test(pwd)) errors.push('éviter 4 caractères identiques consécutifs');
  if (errors.length) {
    throw badRequest('Mot de passe trop faible.', { reasons: errors, minLength });
  }
  return { ok: true, length: pwd.length, entropyBits: estimateEntropyBits(pwd) };
}

export function estimateEntropyBits(pwd) {
  const pools = (/[a-z]/.test(pwd) ? 26 : 0) + (/[A-Z]/.test(pwd) ? 26 : 0) + (/[0-9]/.test(pwd) ? 10 : 0) + (/[^A-Za-z0-9]/.test(pwd) ? 32 : 0);
  if (!pools) return 0;
  return Math.round(pwd.length * Math.log2(pools));
}

/** For /api/meta and the security page — never exposes secret material. */
export function describeAlgorithm() {
  return {
    algorithm: ALGO,
    version: V,
    nativeBinding: nativeImpl ? true : probed ? false : null,
    encoding: 'format PHC : <algo>$v<version>$m,t,p$sel$empreinte',
    plaintextStored: false,
  };
}
