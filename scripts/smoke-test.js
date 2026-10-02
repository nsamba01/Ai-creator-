#!/usr/bin/env node
/**
 * Smoke test — vérifie une instance EN COURD'EXECUTION (native ou Docker).
 *
 *   node scripts/smoke-test.js --base http://127.0.0.1:3000
 *   SMOKE_BASE_URL=... SMOKE_EMAIL=... SMOKE_PASSWORD=... npm run smoke
 *
 * Sans identifiants, les parcours authentifiés sont sautés (et le disent) :
 * le test reste utilisable sur une instance fraîche, sans créer de compte.
 * Aucun mot de passe n'est jamais affiché ; les assertions ne comparent que
 * des statuts, des en-têtes et des compteurs.
 */
import process from 'node:process';
import { readFileSync, statSync } from 'node:fs';
import { loadDotenv } from '../src/config/dotenv.js';

// Les valeurs SMOKE_* peuvent venir du `.env` du projet (l'environnement du
// processus garde la priorité). Aucune valeur n'est journalisée par ce chargeur.
loadDotenv({ root: process.cwd() });

const args = process.argv.slice(2);
function flag(name, def = undefined) {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] ? args[i + 1] : def;
}

const BASE = (flag('base') ?? process.env.SMOKE_BASE_URL ?? 'http://127.0.0.1:3000').replace(/\/$/, '');
const EMAIL = flag('email') ?? process.env.SMOKE_EMAIL ?? '';
let password = flag('password') ?? process.env.SMOKE_PASSWORD ?? '';
// Le mot de passe peut venir d'un fichier (cas du fichier généré par le bootstrap,
// y compris dans un volume monté en lecture seule par le conteneur de test).
// Sa valeur n'est jamais affichée ; un fichier suspect est simplement ignoré.
const PASSWORD_FILE = flag('password-file') ?? process.env.SMOKE_PASSWORD_FILE ?? '';
if (PASSWORD_FILE && !password) {
  try {
    const st = statSync(PASSWORD_FILE);
    if (st.isSymbolicLink() || !st.isFile() || st.size > 4096) {
      throw new Error('fichier inattendu (lien symbolique, spécial ou trop volumineux)');
    }
    password = readFileSync(PASSWORD_FILE, 'utf8').trim();
  } catch (err) {
    console.log(`  – mot de passe depuis ${PASSWORD_FILE} — ACTION NON EXÉCUTÉE, RAISON : ${err.message}`);
  }
}
const NEXT_PASSWORD = flag('new-password') ?? process.env.SMOKE_NEW_PASSWORD ?? '';
const TIMEOUT = Number(flag('timeout-ms') ?? process.env.SMOKE_TIMEOUT_MS ?? 8000);
// Sonde négative : une valeur explicitement non secrète, jamais un littéral qui
// ressemblerait à un mot de passe dans le dépôt.
const PROBE_PASSWORD = process.env.SMOKE_PROBE_PASSWORD ?? 'sonde-negative-non-secrete';

let passed = 0;
let failed = 0;
let skipped = 0;
const jar = new Map();
let csrf = null;

function ok(name, detail = '') {
  passed += 1;
  console.log(`  ✓ ${name}${detail ? ` — ${detail}` : ''}`);
}
function bad(name, detail = '') {
  failed += 1;
  console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ''}`);
}
function skip(name, why) {
  skipped += 1;
  console.log(`  – ${name} — ACTION NON EXÉCUTÉE, RAISON : ${why}`);
}

function absorb(res) {
  for (const line of res.headers.getSetCookie?.() ?? []) {
    const [pair] = String(line).split(';');
    const i = pair.indexOf('=');
    const k = pair.slice(0, i).replace(/^__Host-/, '');
    const v = pair.slice(i + 1);
    if (v === '' || /Max-Age=0|Expires=Thu, 01 Jan 1970/.test(line)) jar.delete(k);
    else jar.set(k, v);
    if (k === 'ps_csrf') csrf = v;
  }
}

async function req(method, path, { body, headers = {}, noCookie = false, noCsrf = false, expectRedirect = false } = {}) {
  const h = { ...headers };
  if (!noCookie && jar.size) h.cookie = [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  if (body !== undefined) h['content-type'] = 'application/json';
  if (!['GET', 'HEAD'].includes(method) && csrf && !noCsrf) h['x-csrf-token'] = csrf;
  const res = await fetch(BASE + path, {
    method,
    headers: h,
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: expectRedirect ? 'manual' : 'manual',
    signal: AbortSignal.timeout(TIMEOUT),
  });
  absorb(res);
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: res.status, headers: res.headers, body: json, text };
}

function section(title) {
  console.log(`\n${title}`);
}

async function main() {
  console.log(`SMOKE TEST — ${BASE}`);

  section('Accessibilité et sonde de vie');
  let health;
  try {
    health = await req('GET', '/healthz');
  } catch (err) {
    bad(`joint ${BASE}`, `${err.name}: ${err.message}`);
    console.log('\nRésultat : échec — l’application n’est pas joignable (lancez `npm start` ou `docker compose up -d --build`).');
    process.exit(1);
  }
  if (health.status === 200 && health.body?.ok === true) ok('GET /healthz', `v${health.body.version} (${health.body.environment})`);
  else bad('GET /healthz', `${health.status} ${health.text.slice(0, 120)}`);

  const ready = await req('GET', '/readyz');
  if (ready.status === 200 && ready.body?.database === 'ready') ok('GET /readyz', 'base de données prête');
  else bad('GET /readyz', `${ready.status} ${ready.text.slice(0, 120)}`);

  const meta = await req('GET', '/api/meta');
  if (meta.status === 200 && Array.isArray(meta.body?.capabilities)) ok('GET /api/meta', `${meta.body.capabilities.length} capacités annoncées`);
  else bad('GET /api/meta', String(meta.status));

  section('En-têtes de sécurité');
  for (const [name, re] of [
    ['Content-Security-Policy', /default-src/],
    ['X-Content-Type-Options', /nosniff/],
    ['X-Frame-Options', /DENY|SAMEORIGIN/],
    ['Referrer-Policy', /no-referrer|same-origin/],
    ['Permissions-Policy', /microphone|geolocation/],
  ]) {
    const v = health.headers.get(name.toLowerCase());
    if (v && re.test(v)) ok(name, v.length > 60 ? `${v.slice(0, 57)}…` : v);
    else bad(name, v ? `valeur inattendue : ${v.slice(0, 60)}` : 'absent');
  }

  section('Authentification et autorisation');
  const unauth = await req('GET', '/api/users', { noCookie: true });
  if (unauth.status === 401 && unauth.body?.error?.code) ok('API protégée', '401 + code machine sans fuite de détail');
  else bad('API protégée', `${unauth.status} ${unauth.text.slice(0, 80)}`);

  const unknown = await req('GET', '/api/nexiste-pas');
  if (unknown.status === 404 && unknown.body?.error?.code === 'NOT_FOUND' && /inconnue|not found/i.test(unknown.body?.error?.message ?? '')) {
    ok('404 normalisé', 'forme d’erreur stable, sans pile ni chemin');
  } else bad('404 normalisé', `${unknown.status} ${unknown.text.slice(0, 80)}`);
  if (!/at .*\.js:\d+/.test(unknown.text) && !/\/home\/|\/app\/|\/usr\//.test(unknown.text)) ok('erreur sans fuite technique', 'ni pile, ni chemin absolu');
  else bad('erreur sans fuite technique', unknown.text.slice(0, 80));

  const noCsrf = await req('POST', '/api/auth/login', { body: { identifier: 'x@y.z', password: PROBE_PASSWORD }, noCsrf: true, noCookie: true });
  if ([400, 401, 403].includes(noCsrf.status)) ok('login public joignable', `statut ${noCsrf.status} sur identifiant inconnu`);
  else bad('login public joignable', String(noCsrf.status));

  jar.clear();
  csrf = null;
  const csrfProbe = await req('POST', '/api/auth/login', { body: { identifier: EMAIL || 'probe@probe.local', password: PROBE_PASSWORD }, noCsrf: true });
  if ([400, 401, 403].includes(csrfProbe.status)) ok('sonde CSRF publique', `statut ${csrfProbe.status} — aucune information ajoutée par la route`);
  else bad('sonde CSRF publique', String(csrfProbe.status));

  if (!EMAIL || !password) {
    skip('parcours authentifié complet', 'aucun identifiant fourni (SMOKE_EMAIL / SMOKE_PASSWORD)');
  } else {
    const login = await req('POST', '/api/auth/login', { body: { identifier: EMAIL, password } });
    if (login.status === 200) {
      ok('connexion', `session établie, csrf ${csrf ? 'présent' : 'ABSENT (!)'}`);
      let me = await req('GET', '/api/auth/me');
      if (me.status === 200 && me.body?.user?.email === EMAIL) ok('session lisible', me.body.user.roles.join('+') || 'sans rôle');
      else bad('session lisible', `${me.status} ${me.text.slice(0, 100)}`);

      if (me.status === 200 && me.body.user.mustChangePassword) {
        ok('première connexion', 'le compte est en changement de mot de passe forcé (attendu après un bootstrap)');
        const next = NEXT_PASSWORD || `Fume-${Math.random().toString(36).slice(2, 10)}-2026!`;
        const change = await req('POST', '/api/auth/change-password', { body: { currentPassword: password, newPassword: next, confirm: next } });
        if (change.status === 200) {
          ok('mot de passe changé', 'la porte « changement obligatoire » est levée');
          password = next;
          me = await req('GET', '/api/auth/me');
          if (me.status === 200 && me.body.user.mustChangePassword) bad('mot de passe changé', 'le compte reste marqué en attente');
        } else {
          skip('suite du parcours authentifié', `changement de mot de passe refusé (${change.status}) — fournissez --new-password`);
        }
      }

      const csrfMissing = await req('POST', '/api/auth/logout', { body: {}, noCsrf: true });
      if (csrfMissing.status === 403 && /CSRF/i.test(JSON.stringify(csrfMissing.body))) ok('CSRF opposable', '403 quand le jeton double-submit manque');
      else bad('CSRF opposable', `${csrfMissing.status} ${csrfMissing.text.slice(0, 80)}`);

      const dash = await req('GET', '/api/admin/dashboard');
      if (dash.status === 200) ok('tableau de bord', `portée ${dash.body.scope}`);
      else bad('tableau de bord', String(dash.status));

      const audit = await req('GET', '/api/admin/audit?limit=5');
      if (audit.status === 200 && Array.isArray(audit.body.items)) ok('journal d’audit', `${audit.body.total} événements, ${audit.body.items.length} affichés`);
      else if (audit.status === 403) ok('journal d’audit', '403 — compte sans audit:read (attendu pour un USER)');
      else bad('journal d’audit', String(audit.status));

      const up = await req('GET', '/api/files?limit=5');
      if (up.status === 200) ok('fichiers', `${up.body.total} entrées visibles (portée ${up.body.scope})`);
      else bad('fichiers', String(up.status));

      const ssrf = await req('POST', '/api/urls/analyze', { body: { url: 'http://169.254.169.254/latest/meta-data/' } });
      if (ssrf.status === 400 && ssrf.body?.error?.code === 'SSRF_BLOCKED') ok('SSRF bloqué', 'endpoint de métadonnées cloud refusé');
      else bad('SSRF bloqué', `${ssrf.status} ${ssrf.text.slice(0, 100)}`);

      const priv = await req('POST', '/api/urls/analyze', { body: { url: `${BASE}/healthz` } });
      if (priv.status === 400) ok('bouclage refusé', 'le serveur ne sert pas de proxy interne');
      else bad('bouclage refusé', String(priv.status));

      const logout = await req('POST', '/api/auth/logout', { body: {} });
      if (logout.status === 200) ok('déconnexion', 'cookies expirés côté client');
      else bad('déconnexion', String(logout.status));
      const after = await req('GET', '/api/auth/me');
      if (after.status === 401) ok('session réellement invalidée', '401 après logout');
      else bad('session réellement invalidée', String(after.status));
    } else {
      bad('connexion', `statut ${login.status} — identifiants refusés ou compte inexistant`);
    }
  }

  section('Interface web');
  const home = await req('GET', '/', { noCookie: true });
  const isSpa = home.status === 200 && /<div id="root"|<script/i.test(home.text);
  if (isSpa) ok('SPA servie', `${home.text.length} octets`);
  else if (home.status === 503) skip('SPA servie', 'build absent — lancez `npm run build` (l’API reste utilisable)');
  else bad('SPA servie', `${home.status}`);

  const asset = /src="\/(assets\/[^"]+)"/.exec(home.text);
  if (asset) {
    const js = await req('GET', `/${asset[1]}`, { noCookie: true });
    if (js.status === 200) ok('bundle JS accessible', asset[1]);
    else bad('bundle JS accessible', String(js.status));
  } else {
    skip('bundle JS accessible', 'référence d’asset non trouvée dans la page');
  }

  console.log(`\nRésultat : ${passed} contrôles OK, ${failed} en échec, ${skipped} non exécutés.`);
  if (failed) {
    console.log('Statut : ÉCHEC.');
    process.exit(1);
  }
  console.log(skipped ? 'Statut : SUCCÈS (avec réserves signalées ci-dessus).' : 'Statut : SUCCÈS.');
  process.exit(0);
}

main().catch((err) => {
  console.error(`  ✗ exception du smoke test : ${err.message}`);
  process.exit(1);
});
