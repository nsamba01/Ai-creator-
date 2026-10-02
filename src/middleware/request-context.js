/**
 * Request context: correlation id, anonymised client fingerprint, timing.
 * Raw IPs are never kept (log-leak safety): only HMAC fingerprints.
 */
import { randomHex, anonymizeIp, anonymizeUserAgent } from '../utils/crypto.js';
import { clientIp } from '../utils/cookies.js';
import { logger } from '../utils/logger.js';

export function createRequestContext(config) {
  return function requestContext(req, res, next) {
    req.id = randomHex(8);
    req.startedAt = Date.now();
    // Stable full path regardless of router mounting (used by policy checks).
    req.pathname = String(req.originalUrl ?? req.url ?? '/').split('?')[0].slice(0, 500);
    req.rawIp = clientIp(req, { trustProxy: config.trustProxy });
    req.ipHash = anonymizeIp(req.rawIp, config.stateSecret);
    req.userAgent = String(req.headers['user-agent'] ?? '').slice(0, 512);
    req.uaHash = anonymizeUserAgent(req.userAgent);
    res.setHeader('X-Request-Id', req.id);
    res.on('finish', () => {
      // Access log line: no query string (it may carry tokens), no cookies.
      const ms = Date.now() - req.startedAt;
      // 501 (« non implémenté », assumé) et 503 (maintenance) ne sont pas des pannes :
      // les journaliser en `error` déclencherait des alertes pour rien.
      const declared = res.statusCode === 501 || res.statusCode === 503;
      const level = res.statusCode >= 500 && !declared ? 'error' : res.statusCode >= 400 ? 'warn' : 'info';
      logger[level](`${req.method} ${req.pathname} ${res.statusCode} ${ms}ms`, {
        requestId: req.id,
        status: res.statusCode,
        durationMs: ms,
        userId: req.user?.id ?? null,
      });
    });
    next();
  };
}

export default createRequestContext;
