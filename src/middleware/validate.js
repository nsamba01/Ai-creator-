/**
 * Minimal, dependency-free input validation.
 *
 * Every write endpoint declares a schema; unknown fields are ignored (never
 * forwarded to SQL), strings are length-capped and control characters are
 * rejected. Combined with fully parameterised statements, this removes both
 * injection and mass-assignment classes of bugs.
 */
import { badRequest } from '../utils/errors.js';

const EMAIL_RE = /^[^\s@,;:"'<>\\]{1,64}@[^\s@,;:"'<>\\]{1,253}$/;
const USERNAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{1,31}$/;
const CONTROL_RE = /[\u0000-\u001f\u007f]/;

function applySpec(name, spec, raw, hasValue) {
  const label = spec.label ?? name;
  if (!hasValue || raw === undefined || raw === null || (typeof raw === 'string' && raw.trim() === '' && spec.type !== 'string-optional')) {
    if (spec.required === false) return { value: spec.default };
    if (spec.default !== undefined) return { value: spec.default };
    throw badRequest(`Champ « ${label} » requis.`, { field: name });
  }

  switch (spec.type) {
    case 'string':
    case 'string-optional': {
      let value = String(raw);
      if (spec.trim !== false) value = value.trim();
      // Les sauts de ligne/tabulations sont autorisés dans les champs documentaires
      // (multiline: true) : un CSV ou un JSON en ligne en contient nécessairement.
      const controlRe = spec.multiline ? /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/ : CONTROL_RE;
      if (controlRe.test(value)) throw badRequest(`« ${label} » contient des caractères de contrôle.`, { field: name });
      const min = spec.min ?? (spec.type === 'string' ? 1 : 0);
      const max = spec.max ?? 2000;
      if (value.length < min) throw badRequest(`« ${label} » : au moins ${min} caractères.`, { field: name });
      if (value.length > max) throw badRequest(`« ${label} » : au plus ${max} caractères.`, { field: name });
      if (spec.lower) value = value.toLowerCase();
      if (spec.pattern && !spec.pattern.test(value)) {
        throw badRequest(`« ${label} » : format invalide (${spec.patternHelp ?? 'format attendu incorrect'}).`, { field: name });
      }
      if (spec.enum && !spec.enum.includes(value)) {
        throw badRequest(`« ${label} » : valeur non autorisée.`, { field: name, allowed: spec.enum });
      }
      return { value };
    }
    case 'email': {
      const value = String(raw).trim().toLowerCase().slice(0, 320);
      if (!EMAIL_RE.test(value)) throw badRequest('Adresse e-mail invalide.', { field: name });
      return { value };
    }
    case 'username': {
      const value = String(raw).trim().slice(0, 32);
      if (!USERNAME_RE.test(value)) {
        throw badRequest('Identifiant invalide : 2-32 caractères [a-z0-9._-], en commençant par une lettre ou un chiffre.', { field: name });
      }
      return { value };
    }
    case 'password': {
      const value = String(raw);
      if (value.length < (spec.min ?? 8)) throw badRequest(`« ${label} » : au moins ${spec.min ?? 8} caractères.`, { field: name });
      if (value.length > 256) throw badRequest('« mot de passe » : trop long.', { field: name });
      return { value };
    }
    case 'int': {
      const n = typeof raw === 'number' ? Math.trunc(raw) : Number.parseInt(String(raw).trim(), 10);
      if (!Number.isFinite(n)) throw badRequest(`« ${label} » : nombre entier attendu.`, { field: name });
      if (spec.min !== undefined && n < spec.min) throw badRequest(`« ${label} » : minimum ${spec.min}.`, { field: name });
      if (spec.max !== undefined && n > spec.max) throw badRequest(`« ${label} » : maximum ${spec.max}.`, { field: name });
      return { value: n };
    }
    case 'bool': {
      if (typeof raw === 'boolean') return { value: raw };
      const s = String(raw).trim().toLowerCase();
      if (['1', 'true', 'yes', 'on'].includes(s)) return { value: true };
      if (['0', 'false', 'no', 'off'].includes(s)) return { value: false };
      throw badRequest(`« ${label} » : booléen attendu.`, { field: name });
    }
    case 'stringArray': {
      const arr = Array.isArray(raw) ? raw : String(raw).split(',');
      const items = arr.map((x) => String(x).trim()).filter(Boolean);
      const max = spec.maxItems ?? 200;
      if (items.length > max) throw badRequest(`« ${label} » : au plus ${max} éléments.`, { field: name });
      if (spec.enum) {
        const bad = items.filter((i) => !spec.enum.includes(i));
        if (bad.length) throw badRequest(`« ${label} » : valeurs non autorisées (${bad.slice(0, 5).join(', ')}).`, { field: name });
      }
      const unique = [...new Set(items)];
      if (spec.lower) return { value: unique.map((i) => i.toLowerCase()) };
      return { value: unique };
    }
    case 'object': {
      // Objet STRICT et plat : c'est la réponse au « aucun champ superflu » pour les objets
      // imbriqués. Sans ce cas, un paramètre de tâche aurait été soit ignoré (donc muet), soit
      // accepté avec n'importe quelles clés (donc masse-assignable).
      if (typeof raw !== 'object' || Array.isArray(raw)) throw badRequest(`« ${label} » : objet attendu.`, { field: name });
      const allowed = Array.isArray(spec.keys) && spec.keys.length ? spec.keys : null;
      const maxKeys = spec.maxKeys ?? 12;
      const maxValueLen = spec.maxValueLen ?? 64;
      const entries = Object.entries(raw);
      if (entries.length > maxKeys) throw badRequest(`« ${label} » : au plus ${maxKeys} champs.`, { field: name });
      const out = {};
      for (const [k, v] of entries) {
        if (allowed && !allowed.includes(k)) {
          throw badRequest(`« ${label} » : champ « ${String(k).slice(0, 40)} » non autorisé.`, { field: name, allowed });
        }
        if (CONTROL_RE.test(String(k))) throw badRequest(`« ${label} » : nom de champ invalide.`, { field: name });
        if (v === null || v === undefined) continue;
        if (typeof v === 'number') {
          if (!Number.isFinite(v)) throw badRequest(`« ${label} » : « ${k} » doit être un nombre fini.`, { field: name });
          out[k] = Math.trunc(v);
        } else if (typeof v === 'boolean') {
          out[k] = v;
        } else if (typeof v === 'string') {
          const text = v.trim();
          if (CONTROL_RE.test(text)) throw badRequest(`« ${label} » : « ${k} » contient des caractères de contrôle.`, { field: name });
          if (text.length > maxValueLen) throw badRequest(`« ${label} » : « ${k} » : au plus ${maxValueLen} caractères.`, { field: name });
          if (spec.enumPerKey?.[k] && !spec.enumPerKey[k].includes(text)) {
            throw badRequest(`« ${label} » : « ${k} » : valeur non autorisée.`, { field: name, allowed: spec.enumPerKey[k] });
          }
          out[k] = text;
        } else {
          throw badRequest(`« ${label} » : « ${k} » doit être un texte court, un entier ou un booléen.`, { field: name });
        }
      }
      return { value: out };
    }
    case 'id': {
      const n = Number(raw);
      if (!Number.isInteger(n) || n <= 0 || n > 2_147_483_647) throw badRequest(`« ${label} » : identifiant invalide.`, { field: name });
      return { value: n };
    }
    default:
      throw new Error(`Spec de validation inconnue: ${spec.type}`);
  }
}

export function validate(input, schema) {
  const out = {};
  for (const [key, spec] of Object.entries(schema)) {
    const hasValue = Object.prototype.hasOwnProperty.call(input ?? {}, key);
    const { value } = applySpec(key, spec, hasValue ? input[key] : undefined, hasValue);
    if (value !== undefined) out[key] = value;
  }
  return out;
}

export function validateBody(schema) {
  return (req, res, next) => {
    try {
      req.validated = validate(req.body ?? {}, schema);
      next();
    } catch (err) {
      next(err);
    }
  };
}

export function validateQuery(schema) {
  return (req, res, next) => {
    try {
      req.validatedQuery = validate(req.query ?? {}, schema);
      next();
    } catch (err) {
      next(err);
    }
  };
}

export const S = {
  email: (o = {}) => ({ type: 'email', ...o }),
  username: (o = {}) => ({ type: 'username', ...o }),
  password: (o = {}) => ({ type: 'password', ...o }),
  text: (o = {}) => ({ type: 'string', ...o }),
  id: (o = {}) => ({ type: 'id', ...o }),
  int: (o = {}) => ({ type: 'int', ...o }),
  bool: (o = {}) => ({ type: 'bool', ...o }),
  list: (o = {}) => ({ type: 'stringArray', ...o }),
};

export { EMAIL_RE, USERNAME_RE };
