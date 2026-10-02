/**
 * Cryptographic helpers.
 *
 * Tokens handed to clients (session, refresh, reset) are NEVER stored in the
 * database in clear form: only `HMAC-SHA256(serverSecret, token)` is stored.
 * A full database dump therefore cannot be replayed.
 */
import crypto from 'node:crypto';

export function randomHex(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

export function randomBase64Url(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

/** Password-friendly random secret avoiding ambiguous glyphs. */
export function randomTempPassword(len = 16) {
  const sets = ['ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!@#$%^&*-_=+'];
  const bytes = crypto.randomBytes(len);
  const chars = [];
  for (let i = 0; i < len; i += 1) {
    const pool = sets[i % sets.length];
    chars.push(pool[bytes[i] % pool.length]);
  }
  // deterministic shuffle with the same entropy source
  for (let i = chars.length - 1; i > 0; i -= 1) {
    const j = bytes[(i * 7 + 3) % bytes.length] % (i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}

export function hmacHex(secret, value, algo = 'sha256') {
  return crypto.createHmac(algo, String(secret)).update(String(value)).digest('hex');
}

export function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

/** Constant-time comparison for equal-length hex/base64 strings. */
export function safeEqual(a, b) {
  const bufA = Buffer.from(String(a ?? ''), 'utf8');
  const bufB = Buffer.from(String(b ?? ''), 'utf8');
  if (bufA.length === 0 || bufB.length === 0 || bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

export function signState(secret, payload) {
  const body = typeof payload === 'string' ? payload : JSON.stringify(payload);
  const encoded = Buffer.from(body, 'utf8').toString('base64url');
  return `${encoded}.${crypto.createHmac('sha256', String(secret)).update(encoded).digest('base64url')}`;
}

export function verifyState(secret, signed) {
  if (typeof signed !== 'string' || !signed.includes('.')) return null;
  const [encoded, sig] = signed.split('.');
  const expected = crypto.createHmac('sha256', String(secret)).update(encoded).digest('base64url');
  if (!safeEqual(sig, expected)) return null;
  try {
    const body = Buffer.from(encoded, 'base64url').toString('utf8');
    try {
      return JSON.parse(body);
    } catch {
      return body;
    }
  } catch {
    return null;
  }
}

/** Non-reversible, non-correlatable identifier for IPs in logs/audit. */
export function anonymizeIp(ip, secret) {
  if (!ip) return null;
  return `ip:${crypto.createHmac('sha256', String(secret)).update(String(ip)).digest('hex').slice(0, 32)}`;
}

export function anonymizeUserAgent(ua) {
  if (!ua) return null;
  return `ua:${sha256Hex(String(ua).slice(0, 512)).slice(0, 32)}`;
}
