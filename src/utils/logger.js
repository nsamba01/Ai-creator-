/**
 * Structured logger with built-in secret redaction.
 *
 * Nothing that looks like a credential may ever be written to stdout, to a
 * file or to `docker logs`. The redaction list is deliberately broad.
 */

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };

/** Keys whose values must never be serialised. */
export const SECRET_KEY_PATTERN =
  /^(password|passwd|pwd|pass|secret|token|authorization|authentication|cookie|set-cookie|apikey|api_key|apikey|access_key|private_key|client_secret|session|sessionid|session_id|refresh|csrf|otp|pin|hash|hashw|digest|credential|credentials|bearer|argon2|bcrypt|seed|salt|signature|reset_token|password_hash)$/i;

const SECRET_KEY_SUBSTRING =
  /(password|passwd|secret|token|authorization|cookie|apikey|api_key|private_key|credential|session_id|csrf|otp_|_otp|reset_|_hash|salt|bearer)/i;

export const REDACTED = '[REDACTED]';

/** Recursively scrubs secret-looking keys / bearer tokens / raw hashes. */
export function redact(value, depth = 0) {
  if (depth > 8) return '[TRUNCATED]';
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') {
    return (
      value
        // Authorization: Bearer xxx / Basic xxx
        .replace(/\b(bearer|basic)\s+[a-z0-9._~+/-]{8,}=*/gi, (_m, p1) => `${p1} ${REDACTED}`)
        // Embedded credentials in URLs: scheme://user:pass@host
        .replace(/([a-z][a-z0-9+.-]*:\/\/)([^/\s:@]+):([^@\s/]+)@/gi, `$1$2:${REDACTED}@`)
        // Common key=value secret shapes
        .replace(
          /\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|session[_-]?id|refresh[_-]?token|access[_-]?token|csrf[_-]?token|authorization)\b(\s*[:=]\s*)("?)[^"',\s}&]+/gi,
          (_m, k, sep, q) => `${k}${sep}${q}${REDACTED}${q ?? ''}`,
        )
        // PHC-style hashes ($argon2id$v=19$... or $2b$12$...)
        .replace(/\$(?:argon2(?:id|i|d)?|2[aby])\$\d{1,3}\$[^\s"'`]+/g, REDACTED)
    );
  }
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (value instanceof Error) {
    return { name: value.name, message: redact(value.message), stack: undefined };
  }
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  if (typeof value === 'object') {
    if (typeof value.toJSON === 'function') {
      try {
        return redact(value.toJSON(), depth + 1);
      } catch {
        /* fall through */
      }
    }
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (SECRET_KEY_PATTERN.test(k) || SECRET_KEY_SUBSTRING.test(k)) out[k] = REDACTED;
      else out[k] = redact(v, depth + 1);
    }
    return out;
  }
  return REDACTED;
}

let configuredLevel = LEVELS.info;
let jsonMode = true;
let sinks = []; // extra write targets (test capture, file sink)

export function configureLogger({ level, json } = {}) {
  if (level && LEVELS[level]) configuredLevel = LEVELS[level];
  if (typeof json === 'boolean') jsonMode = json;
}

export function addLogSink(fn) {
  sinks.push(fn);
  return () => {
    sinks = sinks.filter((f) => f !== fn);
  };
}

function write(level, msg, meta) {
  if (LEVELS[level] < configuredLevel) return;
  const rec = { ts: new Date().toISOString(), level, msg: redact(String(msg)) };
  if (meta && Object.keys(meta).length) rec.meta = redact(meta);
  for (const sink of sinks) {
    try {
      sink(rec);
    } catch {
      /* sinks must never break the app */
    }
  }
  const line = jsonMode
    ? JSON.stringify(rec)
    : `${rec.ts} ${level.toUpperCase().padEnd(5)} ${rec.msg}${rec.meta ? ` ${JSON.stringify(rec.meta)}` : ''}`;
  if (level === 'error') process.stderr.write(line + '\n');
  else process.stdout.write(line + '\n');
}

export const logger = {
  debug: (msg, meta) => write('debug', msg, meta),
  info: (msg, meta) => write('info', msg, meta),
  warn: (msg, meta) => write('warn', msg, meta),
  error: (msg, meta) => write('error', msg, meta),
  child: (base = {}) => ({
    debug: (m, meta) => write('debug', m, { ...base, ...meta }),
    info: (m, meta) => write('info', m, { ...base, ...meta }),
    warn: (m, meta) => write('warn', m, { ...base, ...meta }),
    error: (m, meta) => write('error', m, { ...base, ...meta }),
  }),
};

export default logger;
