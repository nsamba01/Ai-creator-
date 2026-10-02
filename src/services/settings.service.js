/**
 * Administrative settings service.
 *
 * Only allow-listed keys (seeded rows in `settings`) can be read or written;
 * `value_type`, `min_value` and `max_value` columns are the authority. Values
 * typed `secret` are write-only: reads return a masked indicator. This is the
 * "configuration autorisée" of the ADMIN scope.
 */
import { badRequest, notFound } from '../utils/errors.js';
import { logger } from '../utils/logger.js';

export function createSettingsService(db) {
  function parseRow(row) {
    let value;
    try {
      value = JSON.parse(row.value_json);
    } catch {
      value = row.value_json;
    }
    if (row.value_type === 'secret') return { key: row.key, value: null, masked: true, isSecret: true, ...meta(row) };
    return { key: row.key, value, masked: false, isSecret: false, ...meta(row) };
  }

  const meta = (row) => ({
    type: row.value_type,
    min: row.min_value ?? undefined,
    max: row.max_value ?? undefined,
    description: row.description,
    public: Boolean(row.is_public),
    updatedAt: row.updated_at,
    updatedBy: row.updated_by ?? null,
  });

  function all({ includePrivate = false } = {}) {
    const rows = includePrivate
      ? db.all(`SELECT * FROM settings ORDER BY key`)
      : db.all(`SELECT * FROM settings WHERE is_public = 1 ORDER BY key`);
    return rows.map(parseRow);
  }

  function get(key, fallback = undefined) {
    const row = db.get(`SELECT * FROM settings WHERE key = ?`, [key]);
    if (!row) return fallback;
    const parsed = parseRow(row);
    return parsed.value === null && parsed.isSecret ? fallback : parsed.value;
  }

  function number(key, def) {
    const v = get(key, def);
    const n = Number(v);
    return Number.isFinite(n) ? n : def;
  }

  function bool(key, def) {
    const v = get(key, def);
    if (typeof v === 'boolean') return v;
    if (typeof v === 'number') return v !== 0;
    const s = String(v ?? '').toLowerCase();
    if (['1', 'true', 'yes', 'on'].includes(s)) return true;
    if (['0', 'false', 'no', 'off'].includes(s)) return false;
    return def;
  }

  function listKeys() {
    return db.all(`SELECT key, value_type, description, is_public, min_value, max_value FROM settings ORDER BY key`);
  }

  function set({ key, value, actorId = null }) {
    const row = db.get(`SELECT * FROM settings WHERE key = ?`, [key]);
    if (!row) throw notFound(`Clé de configuration inconnue : ${key}`);
    let coerced;
    switch (row.value_type) {
      case 'int': {
        const n = typeof value === 'number' ? Math.trunc(value) : Number.parseInt(String(value).trim(), 10);
        if (!Number.isFinite(n)) throw badRequest(`« ${key} » attend un entier.`);
        if (row.min_value !== null && n < row.min_value) throw badRequest(`« ${key} » : minimum ${row.min_value}.`);
        if (row.max_value !== null && n > row.max_value) throw badRequest(`« ${key} » : maximum ${row.max_value}.`);
        coerced = n;
        break;
      }
      case 'bool': {
        const s = typeof value === 'boolean' ? value : String(value).trim().toLowerCase();
        if (s === true || ['1', 'true', 'yes', 'on'].includes(s)) coerced = true;
        else if (s === false || ['0', 'false', 'no', 'off'].includes(s)) coerced = false;
        else throw badRequest(`« ${key} » attend un booléen.`);
        break;
      }
      case 'json': {
        try {
          coerced = typeof value === 'string' ? JSON.parse(value) : value;
        } catch {
          throw badRequest(`« ${key} » attend du JSON valide.`);
        }
        if (coerced && typeof coerced === 'object' && JSON.stringify(coerced).length > 8000) {
          throw badRequest(`« ${key} » : valeur trop volumineuse.`);
        }
        break;
      }
      case 'secret': {
        const s = String(value ?? '');
        if (s.length > 4096) throw badRequest(`« ${key} » : valeur trop longue.`);
        coerced = s;
        break;
      }
      default: {
        const s = String(value ?? '').trim();
        if (!s) throw badRequest(`« ${key} » : valeur requise.`);
        coerced = s.slice(0, 500);
      }
    }
    db.run(`UPDATE settings SET value_json = ?, updated_at = ?, updated_by = ? WHERE key = ?`, [
      JSON.stringify(coerced),
      new Date().toISOString(),
      actorId,
      key,
    ]);
    logger.info('configuration modifiée', { key, type: row.value_type });
    return parseRow(db.get(`SELECT * FROM settings WHERE key = ?`, [key]));
  }

  function effective() {
    return {
      passwordMinLength: number('security.password_min_length', 12),
      loginMaxAttempts: number('security.login_max_attempts', 5),
      lockoutMinutes: number('security.lockout_minutes', 30),
      sessionTtlMinutes: number('security.session_ttl_minutes', 60),
      selfRegistration: bool('auth.self_registration', false),
      maxUploadMb: number('files.max_upload_mb', 10),
      allowPrivateHosts: bool('urls.allow_private_hosts', false),
      parallelWorkers: number('agents.parallel_workers', 3),
      maintenanceMode: bool('maintenance.mode', false),
      adminMfaHint: bool('security.require_admin_mfa_hint', false),
    };
  }

  return { all, get, number, bool, set, listKeys, effective, parseRow };
}

export default createSettingsService;
