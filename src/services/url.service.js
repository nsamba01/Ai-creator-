/**
 * URL analysis service — controlled outbound fetching.
 *
 * Rules (docs/SECURITY.md, §SSRF):
 *  - http/https only, allowed ports only, no credentials in the URL;
 *  - hostname must not be an internal name and every resolved address must be
 *    public (validated again at connect time via `safeLookup`);
 *  - strict budget: connect/response timeout, byte cap, redirect cap;
 *  - redirects are re-validated (a public host may 302 to 169.254.169.254);
 *  - the response body is never echoed back verbatim: only an extracted,
 *    bounded digest + remote security-header observations;
 *  - every attempt (including blocks) is recorded in `url_analyses`.
 */
import http from 'node:http';
import https from 'node:https';
import zlib from 'node:zlib';
import { URL } from 'node:url';
import { assertSafeUrl, createSafeLookup, resolveSafeAddresses, safeHref, SsrfError } from '../utils/net.js';
import { logger } from '../utils/logger.js';

const UA = 'PrinceNsambaAI/1.0 (+url-analysis; bounded, non-browser)';

export function createUrlService({ db, config, audit }) {
  const policy = {
    allowedProtocols: new Set(['http:', 'https:']),
    allowedPorts: config.url.allowedPorts,
    allowPrivate: config.url.allowPrivate,
  };

  function record(row) {
    try {
      db.run(
        `INSERT INTO url_analyses (requested_by, host, scheme, status, reason, final_host, http_status, bytes, title, metrics_json, created_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
        [
          row.requestedBy ?? null,
          String(row.host).slice(0, 253),
          row.scheme ?? 'https:',
          ['ok', 'redirected', 'blocked', 'error'].includes(row.status) ? row.status : 'error',
          row.reason ? String(row.reason).slice(0, 200) : null,
          row.finalHost ? String(row.finalHost).slice(0, 253) : null,
          row.httpStatus ?? null,
          row.bytes ?? null,
          row.title ? String(row.title).slice(0, 300) : null,
          row.metrics ? JSON.stringify(row.metrics).slice(0, 4000) : null,
          new Date().toISOString(),
        ],
      );
    } catch (err) {
      logger.warn('journalisation url_analyses impossible', { error: err.message });
    }
  }

  function fetchOnce(urlObj, { allowPrivate }) {
    return new Promise((resolve, reject) => {
      const transport = urlObj.protocol === 'https:' ? https : http;
      const req = transport.request(
        {
          protocol: urlObj.protocol,
          hostname: urlObj.hostname,
          port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
          path: `${urlObj.pathname}${urlObj.search}`.replace(/[\u0000-\u001f]",\\]/g, (c) => encodeURIComponent(c)) || '/',
          method: 'GET',
          lookup: createSafeLookup({ allowPrivate }),
          servername: /^[0-9.]+$/.test(urlObj.hostname) ? undefined : urlObj.hostname,
          timeout: config.url.timeoutMs,
          setNoDelay: true,
          headers: {
            'user-agent': UA,
            accept: 'text/html,application/xhtml+xml,text/plain,application/json;q=0.8,*/*;q=0.5',
            'accept-encoding': 'gzip, deflate',
            'accept-language': 'fr,en;q=0.8',
            'connection': 'close',
            'dnt': '1',
          },
        },
        (res) => {
          const chunks = [];
          let size = 0;
          res.on('data', (buf) => {
            size += buf.length;
            if (size > config.url.maxBytes) {
              res.destroy();
              reject(new Error('TOO_LARGE'));
              return;
            }
            chunks.push(buf);
          });
          res.on('end', () => resolve({ res, body: Buffer.concat(chunks) }));
          res.on('error', reject);
        },
      );
      req.setTimeout(config.url.timeoutMs, () => {
        req.destroy(new Error('TIMEOUT'));
      });
      req.on('error', reject);
      req.end();
    });
  }

  async function fetchWithPolicy(startUrl, { allowPrivate }) {
    let current = new URL(startUrl);
    let hops = 0;
    let status = 0;
    const chain = [];
    // eslint-disable-next-line no-constant-condition
    while (true) {
      assertSafeUrl(current.toString(), { ...policy, allowPrivate });
      await resolveSafeAddresses(current.hostname, { allowPrivate });
      const { res, body } = await fetchOnce(current, { allowPrivate });
      status = res.statusCode;
      chain.push({ url: safeHref(current), status });
      if (status >= 300 && status < 400 && res.headers.location) {
        if (hops >= config.url.maxRedirects) {
          const err = new SsrfError('trop de redirections');
          err.code = 'REDIRECT_LIMIT';
          throw err;
        }
        hops += 1;
        const next = new URL(res.headers.location, current);
        current = next;
        continue;
      }
      let decoded = body;
      const enc = String(res.headers['content-encoding'] ?? '').toLowerCase();
      if (enc.includes('gzip')) {
        try {
          decoded = zlib.gunzipSync(body, { maxOutputLength: config.url.maxBytes });
        } catch {
          /* keep raw */
        }
      } else if (enc.includes('deflate')) {
        try {
          decoded = zlib.inflateSync(body, { maxOutputLength: config.url.maxBytes });
        } catch {
          try {
            decoded = zlib.inflateRawSync(body, { maxOutputLength: config.url.maxBytes });
          } catch {
            /* keep raw */
          }
        }
      }
      return { url: current, status, headers: res.headers, body: decoded, redirects: hops, chain };
    }
  }

  async function analyze(rawUrl, { actor = null, req = null } = {}) {
    const started = Date.now();
    let parsed;
    try {
      parsed = assertSafeUrl(rawUrl, policy);
    } catch (err) {
      record({ requestedBy: actor?.id, host: safeHost(rawUrl), scheme: 'unknown', status: 'blocked', reason: err.message, metrics: { stage: 'policy' } });
      audit?.record({
        req,
        actor,
        action: audit.AUDIT.URL_BLOCKED,
        category: 'security',
        outcome: 'blocked',
        severity: 'warning',
        detail: { reason: err.reason, url: safeHref(rawUrl) },
      });
      throw err;
    }

    let fetched;
    try {
      fetched = await fetchWithPolicy(parsed.url.toString(), { allowPrivate: policy.allowPrivate });
    } catch (err) {
      const blocked = err instanceof SsrfError;
      const reason = err?.message === 'TOO_LARGE' ? 'réponse trop volumineuse' : err?.message === 'TIMEOUT' ? 'délai dépassé' : err?.message ?? 'erreur réseau';
      record({
        requestedBy: actor?.id,
        host: parsed.host,
        scheme: parsed.protocol,
        status: blocked ? 'blocked' : 'error',
        reason,
        metrics: { durationMs: Date.now() - started },
      });
      if (blocked) {
        audit?.record({ req, actor, action: audit.AUDIT.URL_BLOCKED, category: 'security', outcome: 'blocked', severity: 'warning', detail: { url: safeHref(rawUrl), reason } });
        throw err;
      }
      const e = new Error(`Récupération impossible : ${String(reason).slice(0, 120)}`);
      e.status = 502;
      e.code = 'UPSTREAM_UNREACHABLE';
      throw e;
    }

    const contentType = String(fetched.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
    const isHtml = /html|xml/.test(contentType);
    const isText = isHtml || /text\/|json|javascript|csv/.test(contentType);
    if (!isText) {
      record({
        requestedBy: actor?.id,
        host: parsed.host,
        finalHost: fetched.url.hostname,
        scheme: parsed.protocol,
        status: fetched.status >= 300 && fetched.status < 400 ? 'redirected' : 'ok',
        httpStatus: fetched.status,
        bytes: fetched.body.length,
        metrics: { contentType, durationMs: Date.now() - started, stage: 'content-type-only' },
      });
      return {
        status: 'ok',
        url: safeHref(fetched.url.toString()),
        httpStatus: fetched.status,
        contentType,
        bytes: fetched.body.length,
        warning: `Contenu de type « ${contentType || 'inconnu'} » : aucune extraction de texte n’est effectuée.`,
      };
    }

    const text = new TextDecoder('utf-8', { fatal: false }).decode(fetched.body);
    const digest = isHtml ? htmlDigest(text) : { title: null, text: text.slice(0, 4000), words: countWords(text), links: 0, headings: [] };
    const remoteHeaders = pickSecurityHeaders(fetched.headers);

    record({
      requestedBy: actor?.id,
      host: parsed.host,
      finalHost: fetched.url.hostname,
      scheme: parsed.protocol,
      status: fetched.redirects ? 'redirected' : 'ok',
      httpStatus: fetched.status,
      bytes: fetched.body.length,
      title: digest.title ?? null,
      metrics: { contentType, redirects: fetched.redirects, durationMs: Date.now() - started, words: digest.words, chain: fetched.chain },
    });
    audit?.record({
      req,
      actor,
      action: audit.AUDIT.URL_ANALYZED,
      category: 'agents',
      detail: { url: safeHref(fetched.url.toString()), httpStatus: fetched.status, bytes: fetched.body.length, redirects: fetched.redirects },
    });

    return {
      status: 'ok',
      url: safeHref(fetched.url.toString()),
      finalUrl: safeHref(fetched.url.toString()),
      httpStatus: fetched.status,
      contentType,
      bytes: fetched.body.length,
      redirects: fetched.redirects,
      chain: fetched.chain,
      durationMs: Date.now() - started,
      title: digest.title,
      meta: digest.meta,
      headings: digest.headings,
      links: digest.links,
      externalLinks: digest.externalLinks,
      words: digest.words,
      excerpt: digest.excerpt,
      forms: digest.forms,
      remoteSecurityHeaders: remoteHeaders,
      observations: buildObservations({ status: fetched.status, digest, remoteHeaders, contentType }),
    };
  }

  function stats(limit = 25) {
    const rows = db.all(
      `SELECT host, scheme, status, reason, http_status, bytes, title, created_at
         FROM url_analyses ORDER BY id DESC LIMIT ?`,
      [limit],
    );
    return {
      total: db.get(`SELECT count(*) AS c FROM url_analyses`).c,
      blocked: db.get(`SELECT count(*) AS c FROM url_analyses WHERE status = 'blocked'`).c,
      recent: rows.map((r) => ({
        host: r.host,
        status: r.status,
        reason: r.reason,
        httpStatus: r.http_status,
        bytes: r.bytes,
        createdAt: r.created_at,
      })),
    };
  }

  return { analyze, stats, fetchWithPolicy };
}

function safeHost(raw) {
  try {
    return new URL(String(raw)).hostname.slice(0, 253);
  } catch {
    return 'invalid';
  }
}

function countWords(s) {
  const m = String(s).match(/[^\s]+/g);
  return m ? m.length : 0;
}

function stripTags(html) {
  return String(html)
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\s+/g, ' ')
    .trim();
}

export function htmlDigest(html) {
  const s = String(html).slice(0, 4_000_000);
  const title = decodeEntities(s.match(/<title[^>]*>([\s\S]{0,300}?)<\/title>/i)?.[1] ?? '') || null;
  const meta = {};
  const metaRe = /<meta[^>]+>/gi;
  let m;
  while ((m = metaRe.exec(s)) !== null) {
    const tag = m[0];
    const name = /(?:name|property)="([^"]{1,60})"/i.exec(tag)?.[1]?.toLowerCase();
    const content = /content="([^"]{0,400})"/i.exec(tag)?.[1];
    if (name && content && ['description', 'og:title', 'og:description', 'og:type', 'keywords', 'robots', 'viewport', 'author'].includes(name)) {
      meta[name] = decodeEntities(content);
    }
  }
  const headings = [];
  const hRe = /<h([1-3])[^>]*>([\s\S]{0,200}?)<\/h\1>/gi;
  let hm;
  while ((hm = hRe.exec(s)) !== null && headings.length < 12) {
    const text = decodeEntities(stripTags(hm[2])).slice(0, 160);
    if (text) headings.push({ level: Number(hm[1]), text });
  }
  const linkRe = /<a[^>]+href="([^"]{1,500})"/gi;
  let lm;
  const external = [];
  let links = 0;
  while ((lm = linkRe.exec(s)) !== null && links < 500) {
    links += 1;
    const href = lm[1];
    if (/^(?:javascript|data|vbscript):/i.test(href)) external.push({ href: href.slice(0, 40), kind: 'dangerous-scheme' });
    else if (/^https?:\/\//i.test(href)) external.push({ href: href.slice(0, 120), kind: 'external' });
  }
  const forms = (s.match(/<form[\s\S]{0,4000}?\/form>/gi) ?? []).slice(0, 5).map((f) => ({
    action: /action="([^"]{0,200})"/i.test(f) ? RegExp.$1 : '',
    method: (/method="([a-z]+)"/i.exec(f)?.[1] ?? 'get').toLowerCase(),
    inputs: (f.match(/<input/gi) ?? []).length,
    hasCsrfField: /name="[^"]*(csrf|authenticity|token|nonce)[^"]*"/i.test(f),
  }));
  const text = stripTags(s);
  return {
    title,
    meta,
    headings,
    links,
    externalLinks: external.slice(0, 20),
    words: countWords(text),
    excerpt: text.slice(0, 1200),
    forms,
  };
}

function decodeEntities(s) {
  return String(s ?? '')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .trim();
}

function pickSecurityHeaders(h) {
  const out = {};
  const wanted = ['server', 'x-powered-by', 'content-security-policy', 'strict-transport-security', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy', 'set-cookie'];
  for (const k of wanted) {
    if (h[k]) out[k] = k === 'set-cookie' ? `${[h[k]].flat().length} cookie(s)` : String(h[k]).slice(0, 200);
  }
  return out;
}

function buildObservations({ status, digest, remoteHeaders, contentType }) {
  const o = [];
  if (status >= 400) o.push({ level: 'warning', message: `Le serveur distant répond ${status}.` });
  if (!remoteHeaders['strict-transport-security']) o.push({ level: 'info', message: 'En-tête Strict-Transport-Security absent côté distant.' });
  if (!remoteHeaders['content-security-policy']) o.push({ level: 'info', message: 'Pas de Content-Security-Policy côté distant.' });
  if (remoteHeaders['x-powered-by']) o.push({ level: 'warning', message: `En-tête d’émpreinte technique exposé : X-Powered-By.` });
  if (digest.forms?.some((f) => !f.hasCsrfField)) o.push({ level: 'warning', message: 'Formulaire distant sans champ anti-CSRF apparent.' });
  if (digest.externalLinks?.some((l) => l.kind === 'dangerous-scheme')) o.push({ level: 'critical', message: 'Liens avec schéma dangereux (javascript:/data:) détectés.' });
  if (contentType.includes('html') && digest.words < 15) o.push({ level: 'info', message: 'Page quasi vide : rendu probablement dépendant de JavaScript.' });
  return o;
}

export default createUrlService;
