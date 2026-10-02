/**
 * HTTP hardening headers (helmet + explicit CSP + no-referrer + sandboxed
 * uploads). CSP avoids `unsafe-inline` for scripts; the SPA ships its CSS as a
 * file, so styles do not need an exception either.
 */
import helmet from 'helmet';

export function createSecurityHeaders(config) {
  const isProd = config.isProd;
  const cspDirectives = {
    defaultSrc: ["'self'"],
    baseUri: ["'none'"],
    scriptSrc: ["'self'"],
    scriptSrcAttr: ["'none'"],
    styleSrc: ["'self'", "'unsafe-inline'"], // Vite injects a small inline style block
    fontSrc: ["'self'", 'data:'],
    imgSrc: ["'self'", 'data:', 'blob:'],
    connectSrc: ["'self'"],
    objectSrc: ["'none'"],
    frameSrc: ["'none'"],
    formAction: ["'self'"],
    frameAncestors: ["'none'"],
    mediaSrc: ["'self'", 'blob:'],
    workerSrc: ["'self'", 'blob:'],
    upgradeInsecureRequests: isProd ? [] : null,
  };

  return [
    helmet({
      contentSecurityPolicy: { useDefaults: false, directives: cspDirectives, reportOnly: false },
      crossOriginEmbedderPolicy: false,
      crossOriginOpenerPolicy: { policy: 'same-origin' },
      crossOriginResourcePolicy: { policy: 'same-origin' },
      referrerPolicy: { policy: 'no-referrer' },
      hidePoweredBy: true,
      noSniff: true,
      xssFilter: true,
      frameguard: { action: 'deny' },
      ieNoOpen: true,
      originAgentCluster: true,
      permittedCrossDomainPolicies: { permittedPolicies: 'none' },
      expectCt: false,
      hsts: isProd
        ? { maxAge: 31_536_000, includeSubDomains: true, preload: true }
        : false,
    }),
    function extraHeaders(req, res, next) {
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('Referrer-Policy', 'no-referrer');
      res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), interest-cohort=(), browsing-topics=()');
      res.setHeader('X-DNS-Prefetch-Control', 'off');
      res.removeHeader('X-Powered-By');
      // All authenticated responses must never be cached (session data).
      if (req.path.startsWith('/api/')) {
        res.setHeader('Cache-Control', 'no-store, max-age=0');
        res.setHeader('Pragma', 'no-cache');
      }
      next();
    },
  ];
}

export default createSecurityHeaders;
