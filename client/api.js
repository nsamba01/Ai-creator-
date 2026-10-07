/**
 * Minimal fetch-based API client.
 *
 * Rules enforced here (defence in depth, the server remains the authority):
 *  - `credentials: 'include'` so the HttpOnly session cookie is used — the
 *    token itself is never readable from JS;
 *  - the CSRF token is read from the `ps_csrf` cookie (the only non-HttpOnly
 *    cookie we set) and sent back in `x-csrf-token`;
 *  - errors are surfaced from the server's structured message;
 *  - a 401 triggers a single refresh attempt before giving up.
 */

let csrfCache = null;

export function getCsrfToken() {
  if (csrfCache) return csrfCache;
  const match = /(?:^|;\s*)ps_csrf=([^;]+)/.exec(document.cookie);
  csrfCache = match ? decodeURIComponent(match[1]) : null;
  return csrfCache;
}

export function primeCsrfToken(token) {
  csrfCache = token ?? null;
}

export class ApiError extends Error {
  constructor(message, { code, status, details, requestId } = {}) {
    super(message);
    this.name = 'ApiError';
    this.code = code ?? 'ERROR';
    this.status = status ?? 0;
    this.details = details;
    this.requestId = requestId;
  }
}

async function request(path, { method = 'GET', body, form, headers = {}, allowRefresh = true, raw = false } = {}) {
  const opts = { method, credentials: 'include', headers: { ...headers } };
  if (form) {
    opts.body = form;
  } else if (body !== undefined) {
    opts.headers['content-type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  if (method !== 'GET' && method !== 'HEAD') {
    const token = getCsrfToken();
    if (token) opts.headers['x-csrf-token'] = token;
  }

  let res;
  try {
    res = await fetch(path, opts);
  } catch (err) {
    throw new ApiError(`Réseau indisponible : ${err.message}`, { code: 'NETWORK' });
  }

  if (res.status === 401 && allowRefresh && method !== 'POST') {
    const refreshed = await tryRefresh();
    if (refreshed) return request(path, { method, body, form, headers, allowRefresh: false });
  }
  if (res.status === 403) {
    const payload = await safeJson(res);
    if (payload?.error?.code === 'PASSWORD_CHANGE_REQUIRED') {
      window.dispatchEvent(new CustomEvent('princesamba:force-password'));
    }
    throw errorFrom(payload, res);
  }
  if (!res.ok) {
    const payload = await safeJson(res);
    throw errorFrom(payload, res);
  }
  if (raw) return res;
  if (res.status === 204) return null;
  const text = await res.text();
  if (!text) return null;
  try {
    const data = JSON.parse(text);
    if (data?.csrfToken) primeCsrfToken(data.csrfToken);
    return data;
  } catch {
    return text;
  }
}

function errorFrom(payload, res) {
  const e = payload?.error ?? {};
  return new ApiError(e.message ?? `Erreur ${res.status}`, {
    code: e.code ?? `HTTP_${res.status}`,
    status: res.status,
    details: e.details,
    requestId: payload?.requestId,
  });
}

async function safeJson(res) {
  try {
    return await res.clone().json();
  } catch {
    return null;
  }
}

let refreshing = null;
function tryRefresh() {
  refreshing ??= fetch('/api/auth/refresh', { method: 'POST', credentials: 'include' })
    .then(async (res) => {
      if (!res.ok) return false;
      const data = await res.json().catch(() => ({}));
      if (data?.csrfToken) primeCsrfToken(data.csrfToken);
      window.dispatchEvent(new CustomEvent('princesamba:session-refreshed'));
      return true;
    })
    .catch(() => false)
    .finally(() => {
      refreshing = null;
    });
  return refreshing;
}

export const api = {
  get: (p, o) => request(p, { ...o, method: 'GET' }),
  post: (p, body, o) => request(p, { ...o, method: 'POST', body }),
  put: (p, body, o) => request(p, { ...o, method: 'PUT', body }),
  patch: (p, body, o) => request(p, { ...o, method: 'PATCH', body }),
  del: (p, o) => request(p, { ...o, method: 'DELETE' }),
  form: (p, form) => request(p, { method: 'POST', form }),
};

export const qs = (params) => {
  const search = new URLSearchParams();
  for (const [k, v] of Object.entries(params ?? {})) {
    if (v !== undefined && v !== null && v !== '') search.set(k, String(v));
  }
  const s = search.toString();
  return s ? `?${s}` : '';
};
