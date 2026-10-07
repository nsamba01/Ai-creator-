/**
 * HTTP hardening headers (helmet + explicit CSP + no-referrer + sandboxed
 * uploads). CSP avoids `unsafe-inline` for scripts; the SPA ships its CSS as a
 * file, so styles do not need an exception either.
 */
import helmet from 'helmet';

export function createSecurityHeaders(config) {
  const isProd = config.isProd;
  // Une liste d'ancêtres n'est jamais un blanc-seing : elle remplace 'none' dans la CSP **et**
  // retire X-Frame-Options, sinon l'en-tête hérité annulerait silencieusement la directive CSP.
  const allowFrames = Array.isArray(config?.frameAncestors) ? config.frameAncestors : [];
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
    frameAncestors: allowFrames.length ? allowFrames : ["'none'"],
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
      frameguard: allowFrames.length ? false : { action: 'deny' },
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
      if (!allowFrames.length) res.setHeader('X-Frame-Options', 'DENY');
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
