/**
 * Configuration loader + hard validation.
 *
 * Design rules enforced here (server side, not UI side):
 *  - no credential is ever hardcoded: the bootstrap admin password comes from
 *    the environment, or is generated and persisted into the data volume;
 *  - in production, weak/absent secrets abort the boot instead of silently
 *    starting an unsafe instance;
 *  - every value is clamped to a safe range.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

export const INSECURE_VALUES = new Set([
  '',
  'change-me',
  'changeme',
  'secret',
  'password',
  'dev-secret',
  'test',
  'insecure',
  'princesamba',
  '000000',
  'default',
]);

const bool = (v, def) => {
  if (v === undefined || v === null || v === '') return def;
  const s = String(v).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(s)) return true;
  if (['0', 'false', 'no', 'off'].includes(s)) return false;
  return def;
};

const int = (v, def, { min = -Infinity, max = Infinity } = {}) => {
  const n = Number.parseInt(String(v ?? ''), 10);
  if (!Number.isFinite(n)) return def;
  return Math.min(max, Math.max(min, n));
};

const list = (v, def = []) =>
  String(v ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean) || def;

export class ConfigError extends Error {
  constructor(msg) {
    super(msg);
    this.name = 'ConfigError';
  }
}

/**
 * Resolves a secret: explicit env value, otherwise a persisted auto-generated
 * one (0600) inside the data dir. Never prints the value anywhere.
 */
function resolveSecret({ name, provided, dataDir, isProd, allowEphemeral }) {
  const ok = typeof provided === 'string' && provided.length >= 32 && !INSECURE_VALUES.has(provided.trim());
  if (ok) return { value: provided, source: 'env' };
  // Une valeur « visiblement non remplacée » : on ne la remplace pas par un
  // secret généré, on refuse de demarrer.
  const looksDeliberate = typeof provided === 'string' && provided.trim().length > 0 && !INSECURE_VALUES.has(provided.trim());
  if (isProd && looksDeliberate) {
    throw new ConfigError(
      `${name} fourni mais trop faible en production (${provided.trim().length} caractère(s), 32 minimum, ou une valeur de la liste des placeholders). ` +
        `Aucun secret ne sera généré à votre place : régénérez (« openssl rand -hex 32 ») et corrigez le déploiement.`,
    );
  }

  const file = path.join(dataDir, `.secret-${name.toLowerCase()}`);
  if (fs.existsSync(file)) {
    const disk = fs.readFileSync(file, 'utf8').trim();
    if (disk.length >= 32) return { value: disk, source: 'volume' };
  }
  if (isProd && !allowEphemeral) {
    throw new ConfigError(
      `${name} manquant ou trop faible en production. Generez-le ("openssl rand -hex 32") et injectez-le via l'environnement ou un secret manager.`,
    );
  }
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const generated = crypto.randomBytes(32).toString('hex');
  try {
    fs.writeFileSync(file, `${generated}\n`, { mode: 0o600, flag: 'wx' });
    return { value: generated, source: 'generated', file };
  } catch {
    // Volume not writable (read-only test environment): keep it in memory only.
    return { value: generated, source: 'ephemeral' };
  }
}

export function loadConfig(env = process.env, overrides = {}) {
  const nodeEnv = (overrides.NODE_ENV ?? env.NODE_ENV ?? 'development').trim();
  const isProd = nodeEnv === 'production';
  const isTest = nodeEnv === 'test';

  const dataDir = path.resolve(ROOT, overrides.DATA_DIR ?? env.DATA_DIR ?? './data');
  const rawDb = String(overrides.DB_PATH ?? env.DB_PATH ?? path.join(dataDir, 'app.db')).trim();
  // « :memory: » est une valeur réservée de SQLite : il ne faut surtout pas la
  // convertir en chemin absolu, sinon un fichier littéralement nommé
  // « :memory: » est créé à la racine du projet.
  const dbPath = rawDb === ':memory:' ? ':memory:' : path.resolve(ROOT, rawDb);
  const uploadDir = path.resolve(ROOT, overrides.UPLOAD_DIR ?? env.UPLOAD_DIR ?? path.join(dataDir, 'uploads'));

  // En production, générer un secret à la place de celui de l’opérateur est une
  // décision explicite : sinon un redémarrage sur un volume vierge invalide
  // toutes les sessions en silence, et un secret fourni mais trop court serait
  // remplacé sans que personne ne s’en aperçoive.
  const allowEphemeralSecrets = !isProd || bool(env.SECRET_ALLOW_GENERATED, false);

  const sessionSecret = resolveSecret({
    name: 'SESSION_SECRET',
    provided: overrides.SESSION_SECRET ?? env.SESSION_SECRET,
    dataDir,
    isProd,
    allowEphemeral: allowEphemeralSecrets,
  });
  const stateSecret = resolveSecret({
    name: 'STATE_SECRET',
    provided: overrides.STATE_SECRET ?? env.STATE_SECRET,
    dataDir,
    isProd,
    allowEphemeral: allowEphemeralSecrets,
  });

  const cfg = {
    env: nodeEnv,
    isProd,
    isTest,
    root: ROOT,
    dataDir,
    host: overrides.HOST ?? env.HOST ?? '0.0.0.0',
    port: int(overrides.PORT ?? env.PORT, 3000, { min: 0, max: 65535 }),
    publicBaseUrl: overrides.PUBLIC_BASE_URL ?? env.PUBLIC_BASE_URL ?? '',
    logLevel: overrides.LOG_LEVEL ?? env.LOG_LEVEL ?? (isProd ? 'info' : 'debug'),
    jsonLogs: bool(env.LOG_JSON, !isTest),

    db: {
      path: dbPath,
      busyTimeoutMs: int(env.DB_BUSY_TIMEOUT_MS, 5000, { min: 100, max: 60000 }),
    },
    uploadDir,

    secrets: {
      session: { source: sessionSecret.source, file: sessionSecret.file },
      state: { source: stateSecret.source, file: stateSecret.file },
    },
    sessionSecret: sessionSecret.value,
    stateSecret: stateSecret.value,

    trustProxy: bool(env.SECURE_PROXY, false),

    cookies: {
      secure:
        (overrides.COOKIE_SECURE ?? env.COOKIE_SECURE ?? 'auto') === 'auto'
          ? isProd
          : bool(overrides.COOKIE_SECURE ?? env.COOKIE_SECURE, isProd),
      sameSite: ['strict', 'lax', 'none'].includes(String(env.COOKIE_SAMESITE ?? 'strict').toLowerCase())
        ? String(env.COOKIE_SAMESITE ?? 'strict').toLowerCase()
        : 'strict',
      prefix: env.COOKIE_PREFIX ?? '',
    },
    csrfEnabled: bool(env.CSRF_PROTECTION, true),

    session: {
      ttlMs: int(env.SESSION_TTL_MINUTES, 60, { min: 1, max: 60 * 24 * 30 }) * 60_000,
      refreshTtlMs: int(env.REFRESH_TOKEN_TTL_DAYS, 14, { min: 1, max: 365 }) * 86_400_000,
    },

    password: {
      minLength: int(env.PASSWORD_MIN_LENGTH, isProd ? 12 : 10, { min: 8, max: 128 }),
      argon2: {
        memoryCost: int(env.ARGON2_MEMORY_KIB, isTest ? 8192 : 19456, { min: 1024, max: 1_048_576 }),
        timeCost: int(env.ARGON2_TIME_COST, isTest ? 1 : 3, { min: 1, max: 32 }),
        parallelism: int(env.ARGON2_PARALLELISM, 2, { min: 1, max: 64 }),
        hashLength: int(env.ARGON2_HASH_LEN, 32, { min: 16, max: 132 }),
      },
    },

    lockout: {
      maxAttempts: int(env.LOGIN_MAX_ATTEMPTS, 5, { min: 3, max: 1000 }),
      windowMs: int(env.LOGIN_WINDOW_MINUTES, 15, { min: 1, max: 1440 }) * 60_000,
      lockMs: int(env.ACCOUNT_LOCK_MINUTES, 30, { min: 1, max: 10080 }) * 60_000,
    },

    limits: {
      apiPerMinute: int(env.API_RATE_LIMIT_PER_MIN, isProd ? 300 : 600, { min: 5, max: 100000 }),
      authPerMinute: int(env.AUTH_RATE_LIMIT_PER_MIN, isProd ? 30 : 60, { min: 3, max: 100000 }),
      urlPerUserPerMinute: int(env.URL_RATE_LIMIT_PER_MIN, 20, { min: 1, max: 10000 }),
    },

    bootstrapAdmin: {
      enabled: bool(overrides.BOOTSTRAP_ADMIN ?? env.BOOTSTRAP_ADMIN, true),
      email: (overrides.BOOTSTRAP_ADMIN_EMAIL ?? env.BOOTSTRAP_ADMIN_EMAIL ?? '').trim().toLowerCase(),
      username: (overrides.BOOTSTRAP_ADMIN_USERNAME ?? env.BOOTSTRAP_ADMIN_USERNAME ?? 'admin').trim(),
      password: overrides.BOOTSTRAP_ADMIN_PASSWORD ?? env.BOOTSTRAP_ADMIN_PASSWORD ?? '',
      passwordFile: path.join(dataDir, 'bootstrap-admin-password'),
    },

    uploads: {
      maxBytes: int(env.MAX_UPLOAD_MB, 10, { min: 1, max: 512 }) * 1024 * 1024,
      quotaBytes: int(env.MAX_QUOTA_MB, 500, { min: 1, max: 20480 }) * 1024 * 1024,
      enforceMagic: bool(env.FILE_SCAN_ENFORCE_MAGIC, true),
    },

    // Phase A de l'agent Video : fenetres de lecture et bornes de coherence.
    // maxBytes est forcement <= uploads.maxBytes : la limite de multer reste la
    // vraie barriere memoire, relever VIDEO_MAX_UPLOAD_MB sans relever
    // MAX_UPLOAD_MB n'aurait donc aucun effet (c'est voulu et documente).
    video: {
      maxBytes: int(env.VIDEO_MAX_UPLOAD_MB, 64, { min: 1, max: 512 }) * 1024 * 1024,
      maxDurationMs: int(env.VIDEO_MAX_DURATION_S, 3600, { min: 1, max: 86_400 }) * 1000,
      probeWindowBytes: int(env.VIDEO_PROBE_WINDOW_KIB, 512, { min: 32, max: 16_384 }) * 1024,
      probeTimeoutMs: int(env.VIDEO_PROBE_TIMEOUT_MS, 10_000, { min: 250, max: 60_000 }),
      useFfprobe: bool(env.VIDEO_USE_FFPROBE, true),
      ffprobePath: String(env.FFPROBE_PATH ?? 'ffprobe').trim() || 'ffprobe',
      quarantineOnFailure: bool(env.VIDEO_QUARANTINE_ON_FAILURE, true),
      // Le processus worker (npm run worker) : kinds traités, cadence, et sort allowed when
      // the loop must run in the web process (tests). Off by default — the media never gets
      // processed inside the request loop.
      workerKinds: String(env.VIDEO_WORKER_KINDS ?? 'probe')
        .split(',')
        .map((k) => k.trim())
        .filter((k) => ['probe', 'transcode', 'transcribe', 'thumbnail', 'moderation'].includes(k)),
      workerPollMs: int(env.VIDEO_WORKER_POLL_MS, 1000, { min: 100, max: 60_000 }),
      workerInProcess: bool(env.VIDEO_WORKER_IN_PROCESS, false),
      // Phase C : outillage media. Le chemin est verifie par safeBinaryPath avant tout spawn ;
      // le delai est borne a 5 minutes meme si un reglage tente de le monter davantage.
      ffmpegPath: String(env.FFMPEG_PATH ?? 'ffmpeg').trim() || 'ffmpeg',
      toolTimeoutMs: int(env.VIDEO_TOOL_TIMEOUT_MS, 30_000, { min: 1000, max: 300_000 }),
    },

    url: {
      timeoutMs: int(env.URL_FETCH_TIMEOUT_MS, 5000, { min: 250, max: 60_000 }),
      maxBytes: int(env.URL_MAX_BYTES, 2_000_000, { min: 1024, max: 50_000_000 }),
      maxRedirects: int(env.URL_MAX_REDIRECTS, 2, { min: 0, max: 5 }),
      allowPrivate: bool(env.URL_ALLOW_PRIVATE_HOSTS, false),
      allowedPorts: new Set(
        list(env.URL_ALLOWED_PORTS, ['80', '443', '8080', '8443'])
          .map((p) => Number.parseInt(p, 10))
          .filter((n) => Number.isFinite(n)),
      ),
    },

    cors: {
      allowedOrigins: new Set(list(env.CORS_ALLOWED_ORIGINS, ['http://localhost:3000', 'http://127.0.0.1:3000'])),
    },

    // Encadrement de la page (iframe). Le refus est le défaut, et il n'existe aucun
    // « allow all » : une liste d'origines complètes avec schéma, ou rien.
    frameAncestors: (() => {
      const raw = String(env.CSP_FRAME_ANCESTORS ?? '').trim();
      if (!raw || raw === "'none'" || raw.toLowerCase() === 'none') return [];
      const parts = raw.split(/[\s,]+/).filter(Boolean);
      if (!parts.length) return [];
      const shaped = parts.filter((p) => !/^https?:\/\//.test(p));
      if (shaped.length) {
        throw new ConfigError(`CSP_FRAME_ANCESTORS : chaque origine doit commencer par http:// ou https:// (${shaped.join(', ')}).`);
      }
      const bad = parts.filter((p) => p === '*' || p === 'https://*' || !/^[A-Za-z0-9.*_:/+-]+$/.test(p));
      if (bad.length) throw new ConfigError(` CSP_FRAME_ANCESTORS refusé (${bad.join(', ')}) : aucun joker global, aucun caractère inattendu.`);
      return parts;
    })(),

    bodyLimit: (() => {
      const raw = String(env.JSON_BODY_LIMIT ?? '1mb').trim().toLowerCase();
      const mult = raw.endsWith('kb') ? 1024 : raw.endsWith('mb') ? 1024 * 1024 : 1;
      const n = Number.parseInt(raw, 10) * mult;
      return Number.isFinite(n) && n > 0 ? Math.min(n, 8 * 1024 * 1024) : 1024 * 1024;
    })(),

    // La porte de derives « auth off » n'est jamais acceptable en production :
    // on refuse de demarrer plutt que d'ignorer silencieusement le rglage.
    authDisabledRequested: bool(env.DISABLE_AUTH_FOR_TESTS, false),
    disableAuthForTests: bool(env.DISABLE_AUTH_FOR_TESTS, false) && !isProd,
  };

  // ---- production safety gate -------------------------------------------
  if (isProd) {
    const problems = [];
    if (cfg.cookies.sameSite === 'none' && !cfg.cookies.secure)
      problems.push(' COOKIE_SAMESITE=none exige COOKIE_SECURE=1.');
    if (!cfg.csrfEnabled) problems.push(' CSRF_PROTECTION doit rester actif en production.');
    if (cfg.authDisabledRequested) problems.push(' DISABLE_AUTH_FOR_TESTS est interdit en production.');
    if (cfg.cors.allowedOrigins.has('*')) problems.push(' CORS_ALLOWED_ORIGINS=* interdit avec des cookies.');
    if (cfg.video.maxBytes > cfg.uploads.maxBytes) {
      cfg._videoHint =
        `VIDEO_MAX_UPLOAD_MB (${Math.round(cfg.video.maxBytes / 1048576)} Mo) depasse MAX_UPLOAD_MB (${Math.round(
          cfg.uploads.maxBytes / 1048576,
        )} Mo) : la limite globale s’applique d’abord ; relevez MAX_UPLOAD_MB pour accepter de plus grosses videos.`;
    }
    if (String(env.HOST ?? '0.0.0.0') === '127.0.0.1' && !env.FORCE_LOCALHOST_WARNING) {
      // not fatal, just a hint logged later
      cfg._hostHint = 'HOST=127.0.0.1 rendra le service injoignable depuis le réseau/le proxy.';
    }
    if (problems.length) throw new ConfigError(`Configuration refusée en production:${problems.join('')}`);
  }

  return Object.freeze({
    ...cfg,
    db: Object.freeze(cfg.db),
    cookies: Object.freeze(cfg.cookies),
    session: Object.freeze(cfg.session),
    password: Object.freeze({ ...cfg.password, argon2: Object.freeze(cfg.password.argon2) }),
    lockout: Object.freeze(cfg.lockout),
    limits: Object.freeze(cfg.limits),
    bootstrapAdmin: Object.freeze(cfg.bootstrapAdmin),
    uploads: Object.freeze(cfg.uploads),
    video: Object.freeze(cfg.video),
    url: Object.freeze({ ...cfg.url, allowedPorts: cfg.url.allowedPorts }),
    cors: Object.freeze({ allowedOrigins: cfg.cors.allowedOrigins }),
    frameAncestors: Object.freeze(cfg.frameAncestors),
    secrets: Object.freeze(cfg.secrets),
  });
}

export default loadConfig;
