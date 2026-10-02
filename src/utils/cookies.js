/**
 * Cookie helpers (no dependency).
 *
 * Every session cookie is HttpOnly + SameSite + Path=/ ; `Secure` is enabled
 * automatically in production (and can be forced with COOKIE_SECURE=1).
 * The CSRF cookie is intentionally readable by JS (double-submit pattern) but
 * is *also* bound to the session row server-side.
 */

export const COOKIE_NAMES = {
  session: 'ps_session',
  refresh: 'ps_refresh',
  csrf: 'ps_csrf',
};

export function parseCookies(header = '') {
  const out = {};
  if (typeof header !== 'string' || !header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (!k) continue;
    try {
      out[k] = decodeURIComponent(v);
    } catch {
      out[k] = v;
    }
  }
  return out;
}

export function serializeCookie(name, value, opts = {}) {
  const {
    maxAge = undefined,
    expires = undefined,
    path = '/',
    httpOnly = true,
    secure = false,
    sameSite = 'Strict',
    domain = undefined,
  } = opts;
  const parts = [`${name}=${value === undefined || value === null ? '' : encodeURIComponent(String(value))}`];
  if (path) parts.push(`Path=${path}`);
  if (maxAge !== undefined) parts.push(`Max-Age=${Math.max(0, Math.floor(maxAge))}`);
  if (expires) parts.push(`Expires=${new Date(expires).toUTCString()}`);
  parts.push(`SameSite=${sameSite}`);
  if (domain) parts.push(`Domain=${domain}`);
  if (httpOnly) parts.push('HttpOnly');
  if (secure) parts.push('Secure');
  return parts.join('; ');
}

export function clearCookie(name, opts = {}) {
  return serializeCookie(name, '', { ...opts, maxAge: 0, expires: new Date(0) });
}

export function clientIp(req, { trustProxy = false } = {}) {
  if (trustProxy) {
    const fwd = req.headers['x-forwarded-for'];
    const value = Array.isArray(fwd) ? fwd[0] : fwd;
    if (value) {
      const first = String(value).split(',')[0].trim();
      if (first && first.length <= 64) return first;
    }
  }
  return (req.socket?.remoteAddress ?? req.ip ?? '').replace(/^::ffff:/, '') || 'unknown';
}
