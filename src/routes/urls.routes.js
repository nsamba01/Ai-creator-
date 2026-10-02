/**
 * URL analysis routes.
 *
 * Rate-limited, permission-gated, and strictly SSRF-screened by the service.
 * Errors coming from the policy are mapped to 400 with a reason (never a raw
 * stack), and both successes and blocks are journalled.
 */
import { Router } from 'express';
import { wrap, noStore } from './_helpers.js';
import { validateBody, S } from '../middleware/validate.js';
import { badRequest, tooManyRequests } from '../utils/errors.js';
import { SsrfError } from '../utils/net.js';
import { safeHref } from '../utils/net.js';

export function createUrlRoutes(runtime) {
  const router = Router();
  const { urls, audit, config, rateLimit, rbac } = runtime;
  const { requireAuth, requirePermission } = runtime.middlewares;

  router.post('/analyze', requireAuth, requirePermission('urls:analyze'), noStore, validateBody({
    url: S.text({ min: 8, max: 2000, label: 'url', pattern: /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/\S+$/, patternHelp: 'URL absolue http(s) attendue' }),
  }), wrap(async (req, res) => {
    const { url } = req.validated;
    const gate = rateLimit.consume(`url:${req.user.id}`, 1, {
      max: config.limits.urlPerUserPerMinute,
      windowMs: 60_000,
      blockMs: 60_000,
    });
    if (!gate.allowed) throw tooManyRequests('Trop d’analyses d’URL. Attendez une minute.', 60);
    try {
      const out = await urls.analyze(url, { actor: req.user, req });
      res.json(out);
    } catch (err) {
      if (err instanceof SsrfError) {
        res.status(400).json({ error: { code: 'SSRF_BLOCKED', message: err.message, detail: err.detail, url: safeHref(url) } });
        return;
      }
      if (err?.code === 'UPSTREAM_UNREACHABLE') {
        res.status(502).json({ error: { code: 'UPSTREAM_UNREACHABLE', message: err.message, url: safeHref(url) } });
        return;
      }
      throw err;
    }
  }));

  router.get('/stats', requireAuth, requirePermission('security:read'), noStore, wrap(async (req, res) => {
    res.json({ ...urls.stats(25), policy: { allowPrivate: config.url.allowPrivate, maxBytes: config.url.maxBytes, timeoutMs: config.url.timeoutMs, allowedPorts: [...config.url.allowedPorts], maxRedirects: config.url.maxRedirects } });
  }));

  /** Lets the UI show whether internal targets are permitted (no fetch). */
  router.post('/preflight', requireAuth, requirePermission('urls:analyze'), noStore, validateBody({ url: S.text({ min: 8, max: 2000 }) }), wrap(async (req, res) => {
    const { assertSafeUrl } = await import('../utils/net.js');
    try {
      const parsed = assertSafeUrl(req.validated.url, {
        allowedProtocols: new Set(['http:', 'https:']),
        allowedPorts: config.url.allowedPorts,
        allowPrivate: config.url.allowPrivate,
      });
      res.json({ allowed: true, host: parsed.host, port: parsed.port, scheme: parsed.protocol });
    } catch (err) {
      res.status(400).json({ allowed: false, reason: err.message });
    }
  }));

  return router;
}

export default createUrlRoutes;
