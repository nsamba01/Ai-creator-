/**
 * Network safety helpers: SSRF guard.
 *
 * The document/URL analysis features must never turn the agent into a proxy
 * towards internal systems. Three layers:
 *   1. URL policy (scheme, no credentials, allowed ports, deny-list of host
 *      names such as metadata endpoints and `.local`);
 *   2. address classification of every resolved record (v4 + v6, including
 *      IPv4-mapped, 6to4 and Teredo embeds);
 *   3. a `lookup` hook used at *connect* time, so DNS rebinding
 *      (public name → 127.0.0.1 after resolution) is caught as well.
 */
import dns from 'node:dns/promises';
import net from 'node:net';

export class SsrfError extends Error {
  constructor(reason, detail) {
    super(`Accès réseau refusé : ${reason}`);
    this.name = 'SsrfError';
    this.code = 'SSRF_BLOCKED';
    this.status = 400;
    this.reason = reason;
    this.detail = detail;
  }
}

const IPV4_BLOCKED = [
  ['0.0.0.0', 8], // this network
  ['10.0.0.0', 8],
  ['100.64.0.0', 10], // CGNAT
  ['127.0.0.0', 8],
  ['169.254.0.0', 16], // link-local incl. 169.254.169.254 metadata
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
];

const DENY_HOSTS = new Set([
  'metadata.google.internal',
  'metadata',
  'instance-data',
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
  'host.docker.internal',
  'gateway.docker.internal',
  'kubernetes.default.svc',
]);

const DENY_SUFFIXES = ['.local', '.internal', '.localdomain', '.cluster.local', '.home', '.lan', '.localdomain'];

function ipv4ToLong(ip) {
  const parts = ip.split('.').map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function inCidrV4(ip, [base, bits]) {
  const ipLong = ipv4ToLong(ip);
  const baseLong = ipv4ToLong(base);
  if (ipLong === null || baseLong === null) return true; // unparseable => refuse
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipLong & mask) >>> 0 === (baseLong & mask) >>> 0;
}

function expandIpv6(ip) {
  let s = String(ip);
  const zone = s.indexOf('%');
  if (zone >= 0) s = s.slice(0, zone);
  if (!s.includes(':')) return null;
  let [head, tail] = s.split('::');
  const headParts = head ? head.split(':').filter((x) => x !== '') : [];
  let tailParts = tail !== undefined && tail !== '' ? tail.split(':').filter((x) => x !== '') : tail === '' ? [] : [];
  if (tailParts.length && net.isIPv4(tailParts[tailParts.length - 1])) {
    const v4 = ipv4ToLong(tailParts.pop());
    if (v4 === null) return null;
    tailParts.push(((v4 >>> 16) & 0xffff).toString(16), (v4 & 0xffff).toString(16));
  }
  const all = tail === undefined ? headParts : [...headParts, ...Array(Math.max(0, 8 - headParts.length - tailParts.length)).fill('0'), ...tailParts];
  if (all.length !== 8) return null;
  const words = all.map((h) => {
    if (!/^[0-9a-fA-F]{1,4}$/.test(h)) return null;
    return Number.parseInt(h, 16);
  });
  if (words.some((w) => w === null)) return null;
  return words;
}

/** True when the address must not be reached from the application. */
export function isBlockedAddress(ip) {
  const value = String(ip ?? '').trim().replace(/^\[|\]$/g, '');
  if (!value) return true;
  if (net.isIPv4(value)) return IPV4_BLOCKED.some((cidr) => inCidrV4(value, cidr));
  if (net.isIPv6(value)) {
    const words = expandIpv6(value);
    if (!words) return true;
    const hex = words.map((w) => w.toString(16).padStart(4, '0')).join('');
    const first = words[0];
    // :: and ::1
    if (hex === '00000000000000000000000000000000' || hex === '00000000000000000000000000000001') return true;
    // IPv4-mapped (::a.b.c.d) and IPv4-translated (::ffff:0:a.b.c.d) forms:
    // the embedded address must be classified too, otherwise `::ffff:127.0.0.1`
    // would slip through the filter.
    if (words.slice(0, 5).every((w) => w === 0) && (words[5] === 0xffff || words[5] === 0)) {
      const a = (words[6] >> 8) & 0xff;
      const b = words[6] & 0xff;
      const c = (words[7] >> 8) & 0xff;
      const d = words[7] & 0xff;
      if (words[5] === 0xffff || (a || b || c || d)) return isBlockedAddress(`${a}.${b}.${c}.${d}`);
    }
    // 6to4 2002::/16 embeds an IPv4 address in words 1 and 2.
    if (hex.startsWith('2002')) {
      const a = (words[1] >> 8) & 0xff;
      const b = words[1] & 0xff;
      const c = (words[2] >> 8) & 0xff;
      const d = words[2] & 0xff;
      return isBlockedAddress(`${a}.${b}.${c}.${d}`);
    }
    if (first >= 0xff00) return true; // multicast
    if ((first & 0xfe00) === 0xfc00) return true; // unique-local fc00::/7
    if ((first & 0xffc0) === 0xfe80) return true; // link-local
    if ((first & 0xffc0) === 0x2001 && hex.slice(4, 8) === '0000') return true; // Teredo-ish patterns
    return false;
  }
  return true; // anything unparseable is refused
}

export function assertPublicAddress(ip) {
  if (isBlockedAddress(ip)) throw new SsrfError('adresse interne ou non routable', { ip: undefined });
  return ip;
}

/**
 * URL policy. Returns a parsed URL or throws SsrfError.
 */
export function assertSafeUrl(raw, { allowedProtocols = new Set(['http:', 'https:']), allowedPorts = new Set([80, 443, 8080, 8443]), allowPrivate = false, maxUrlLength = 2000 } = {}) {
  const str = String(raw ?? '').trim();
  if (!str) throw new SsrfError('URL vide');
  if (str.length > maxUrlLength) throw new SsrfError('URL trop longue');
  let url;
  try {
    url = new URL(str);
  } catch {
    throw new SsrfError('URL invalide');
  }
  if (!allowedProtocols.has(url.protocol)) throw new SsrfError(`protocole non autorisé (${url.protocol})`);
  if (url.username || url.password) throw new SsrfError('identifiants dans l’URL');
  if (url.search.includes('://') || url.hash.includes('://')) throw new SsrfError('URL imbriquée suspecte');
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (!host) throw new SsrfError('hôte manquant');
  if (DENY_HOSTS.has(host) || DENY_SUFFIXES.some((s) => host.endsWith(s))) throw new SsrfError('hôte interne');
  if (host === 'metadata.google.internal' || host.endsWith('.amazonaws.com') && host.includes('metadata')) throw new SsrfError('endpoint metadata');
  if (/^0\.0\.0\.0$|^127\.|^169\.254\.|^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\.|^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(host)) {
    if (!allowPrivate) throw new SsrfError('adresse IP privée en littéral');
  }
  if (net.isIP(host) && !allowPrivate) assertPublicAddress(host);
  const port = url.port ? Number.parseInt(url.port, 10) : url.protocol === 'https:' ? 443 : 80;
  if (!allowedPorts.has(port)) throw new SsrfError(`port non autorisé (${port})`);
  return { url, host, port, protocol: url.protocol, blocked: false };
}

/**
 * Resolves and validates a hostname. Returns the list of safe addresses.
 */
export async function resolveSafeAddresses(host, { port = 443, family = 0, allowPrivate = false } = {}) {
  if (net.isIP(host)) {
    if (!allowPrivate) assertPublicAddress(host);
    return [host];
  }
  let records;
  try {
    records = await dns.lookup(host, { all: true, verbatim: true });
  } catch (err) {
    throw new SsrfError('résolution impossible', { code: err?.code });
  }
  if (!records.length) throw new SsrfError('aucun enregistrement');
  const safe = records.map((r) => r.address);
  if (!allowPrivate) {
    for (const addr of safe) {
      if (isBlockedAddress(addr)) throw new SsrfError('le nom résout vers une adresse interne');
    }
  }
  if (family && safe.length) {
    const filtered = safe.filter((a) => (family === 4 ? net.isIPv4(a) : net.isIPv6(a)));
    if (filtered.length) return filtered;
  }
  return safe;
}

/**
 * A `dns.lookup` compatible callback for http/https.request that refuses any
 * private address at connection time (defeats DNS rebinding).
 */
export function createSafeLookup({ allowPrivate = false } = {}) {
  return function safeLookup(hostname, options, callback) {
    const opts = typeof options === 'object' && options ? options : { all: false };
    const done = typeof options === 'function' ? options : callback;
    dns
      .lookup(hostname, { ...opts, verbatim: true, all: true })
      .then((records) => {
        if (!records.length) return done(new SsrfError('résolution vide'), []);
        if (!allowPrivate) {
          for (const r of records) {
            if (isBlockedAddress(r.address)) return done(new SsrfError(`adresse interne refusée (${hostname})`), []);
          }
        }
        if (opts.all) return done(null, records);
        return done(null, records[0].address, records[0].family);
      })
      .catch((err) => done(err instanceof SsrfError ? err : new SsrfError('résolution impossible', { code: err?.code }), undefined));
  };
}

export function safeHref(url) {
  try {
    const u = new URL(String(url));
    u.username = '';
    u.password = '';
    return `${u.protocol}//${u.host}${u.pathname}`.slice(0, 300);
  } catch {
    return '(url invalide)';
  }
}
