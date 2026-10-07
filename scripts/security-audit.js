#!/usr/bin/env node
/**
 * Audit de securite du depot (statique) + verifications d’execution.
 *
 *   npm run audit
 *   node scripts/security-audit.js [--json] [--strict]
 *
 * Ce script n’imprime JAMAIS une valeur sensible : il signale la présence, la
 * ligne, et recommande la rotation. Il ne supprime rien de lui-même — la
 * suppression d’un secret des sources est une décision humaine (historique Git
 * compris), donc chaque constat est accompagné de l’action à mener.
 */
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
// lint-allow: l'auditeur doit exécuter `git ls-files` et `npm audit` en lecture
// seule, avec un délai dur et sans shell (arguments en liste, aucune entrée utilisateur).
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const asJson = process.argv.includes('--json');
const strict = process.argv.includes('--strict');

const findings = [];
const info = [];
function add(level, title, where, advice) {
  findings.push({ level, title, where, advice });
}

const IGNORED_DIRS = new Set(['node_modules', '.git', 'dist', 'data', 'coverage', '.cache']);
function* walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === '.DS_Store') continue;
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (IGNORED_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
      yield* walk(p);
    } else yield p;
  }
}

const SECRET_RULES = [
  { why: 'clé AWS', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { why: 'clé privée', re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { why: 'jeton GitHub', re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/ },
  { why: 'jeton Slack', re: /bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { why: 'jeton Google API', re: /\bAIza[0-9A-Za-z_-]{30,}\b/ },
  { why: 'jeton OpenAI', re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/ },
  { why: 'JWT compact', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/ },
  { why: 'URL de base avec identifiants', re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^/\s:@]+:[^/\s@]{3,}@/ },
  { why: 'secret attribué en clair', re: /\b(?:SESSION_SECRET|STATE_SECRET|COOKIE_PREFIX|_API_KEY|_TOKEN|_PASSWORD)\s*[:=]\s*['"]?(?!\$|process\.env|<[a-z_]+>)[A-Za-z0-9+/=_.-]{16,}/ },
];

// lint-allow: arguments figés, pas de shell, cwd du dépôt (voir docs/SECURITY-POLICY.md § 2).
const git = (args) => spawnSync('git', args, { cwd: ROOT, encoding: 'utf8' });

// Un fichier ignoré par Git (`git check-ignore`) ne peut pas fuiter par le dépôt :
// ses secrets sont locaux. On ne le signale pas comme constat, on le compte — pour
// que le constat reste interprétable en CI sans aveugler le portique sur une vraie
// fuite publiée. Un fichier ignoré mais QUAND MÊME suivi reste traité plus bas.
const trackedSet = new Set((git(['ls-files']).stdout || '').split('\n').filter(Boolean));
const ignoredCache = new Map();
function isGitIgnored(rel) {
  if (!ignoredCache.has(rel)) ignoredCache.set(rel, git(['check-ignore', '-q', '--', rel]).status === 0);
  return ignoredCache.get(rel);
}
// Un chemin ignoré MAIS suivi (typiquement `git add -f .env`) n'est pas protégé :
// il garde toute sa sévérité.
const offLimits = (rel) => isGitIgnored(rel) && !trackedSet.has(rel);
let ignoredHits = 0;

const textFiles = [];
for (const file of walk(ROOT)) {
  const rel = path.relative(ROOT, file).split(path.sep).join('/');
  if (/\.(png|jpg|jpeg|gif|webp|ico|woff2?|ttf|map)$/i.test(rel)) continue;
  if (rel === 'scripts/security-audit.js' || rel === 'scripts/lint.js') continue; // motifs par définition
  textFiles.push(rel);
  let content;
  try {
    content = fs.readFileSync(file, 'utf8');
  } catch {
    continue;
  }
  content.split('\n').forEach((line, i) => {
    for (const { why, re } of SECRET_RULES) {
      if (re.test(line)) {
        const fixture = /^(tests\/|docs\/)/.test(rel) && !/-----BEGIN/.test(line);
        if (fixture) continue;
        if (offLimits(rel)) {
          ignoredHits += 1;
          continue;
        }
        add('critical', `Secret probable : ${why}`, `${rel}:${i + 1}`, 'Retirer des sources, purger l’historique Git, révoquer puis régénérer la valeur.');
      }
    }
  });
}

/* ---- .env suivi par Git ? ------------------------------------------------ */
const tracked = git(['ls-files']);
if (tracked.status === 0) {
  const files = tracked.stdout.split('\n');
  const envTracked = files.filter((f) => /(^|\/)\.env($|\.)/.test(f) && !/\.env\.example$/.test(f));
  if (envTracked.length) add('critical', 'fichier .env suivi par Git', envTracked.join(', '), '`git rm --cached` puis ajouter à .gitignore et révoquer les valeurs.');
  else info.push('.env non suivi par Git ✔');
  const keyTracked = files.filter((f) => /(\.pem|\.key|id_rsa|\.p12|\.pfx)$/i.test(f));
  if (keyTracked.length) add('critical', 'matériel clé privé suivi par Git', keyTracked.join(', '), 'Révoquer la paire et la sortir du dépôt.');
  else info.push('aucun fichier de clé privée dans l’index ✔');
  for (const needed of ['.gitignore', '.dockerignore']) {
    if (!files.includes(needed) && !fs.existsSync(path.join(ROOT, needed))) add('high', `${needed} absent`, needed, 'nécessaire pour exclure secrets et artifacts du dépôt/de l’image.');
  }
} else {
  info.push('ACTION NON EXÉCUTÉE : index Git illisible (RAISON : git indisponible ou dépôt non initialisé)');
}

/* ---- gitignore couvre-t-il les chemins sensibles ? ------------------------- */
const gi = fs.existsSync(path.join(ROOT, '.gitignore')) ? fs.readFileSync(path.join(ROOT, '.gitignore'), 'utf8') : '';
for (const need of [/^\/?data\/?$/m, /^\.env$/m, /^\*\.db(-wal|-shm)?$/m]) {
  if (!need.test(gi)) add('high', '.gitignore incomplet', `motif manquant : ${need}`, 'les bases SQLite et les secrets locaux doivent rester hors du dépôt.');
}

/* ---- secrets générés : permissions sur disque --------------------------- */
const dataDir = path.join(ROOT, process.env.DATA_DIR ?? 'data');
if (fs.existsSync(dataDir)) {
  for (const f of fs.readdirSync(dataDir)) {
    if (!/^\.secret/.test(f)) continue;
    const st = fs.statSync(path.join(dataDir, f));
    const mode = (st.mode & 0o777).toString(8);
    if ((st.mode & 0o077) !== 0) add('high', `secret local lisible par le groupe/les tiers (${f})`, `mode ${mode}`, 'Repasser en 0600 : le fichier donne accès à toutes les sessions.');
    else info.push(`secret local ${f} en 0600 ✔`);
  }
}

/* ---- garde-fous de configuration (exécution réelle de loadConfig) -------- */
let guardsChecked = 0;
try {
  const { loadConfig } = await import('../src/config/env.js');
  const mustRefuse = [
    ['CSRF désactivé en production', { NODE_ENV: 'production', HOST: '0.0.0.0', CSRF_PROTECTION: '0', SESSION_SECRET: 'x'.repeat(48), STATE_SECRET: 'y'.repeat(48) }],
    ['cookie non Secure avec SameSite=none', { NODE_ENV: 'production', HOST: '0.0.0.0', COOKIE_SAMESITE: 'none', COOKIE_SECURE: '0', SESSION_SECRET: 'x'.repeat(48), STATE_SECRET: 'y'.repeat(48) }],
    ['CORS ouvert avec cookies', { NODE_ENV: 'production', HOST: '0.0.0.0', CORS_ALLOWED_ORIGINS: '*', SESSION_SECRET: 'x'.repeat(48), STATE_SECRET: 'y'.repeat(48) }],
    ['porte de contournement d’auth', { NODE_ENV: 'production', HOST: '0.0.0.0', DISABLE_AUTH_FOR_TESTS: '1', SESSION_SECRET: 'x'.repeat(48), STATE_SECRET: 'y'.repeat(48) }],
    ['secret trop faible', { NODE_ENV: 'production', HOST: '0.0.0.0', SESSION_SECRET: 'abc', STATE_SECRET: 'abc' }],
  ];
  for (const [label, env] of mustRefuse) {
    try {
      loadConfig(env, {});
      add('critical', `configuration dangereuse acceptée : ${label}`, 'src/config/env.js', 'Durcir la garde : le démarrage doit échouer, pas avertir.');
    } catch {
      guardsChecked += 1;
    }
  }
  if (guardsChecked === mustRefuse.length) info.push(`${guardsChecked} configurations dangereuses refusées au démarrage ✔`);

  // Le mode maintenance et les limites doivent rester configurables.
  const cfg = loadConfig({ NODE_ENV: 'test', LOG_LEVEL: 'silent', DATA_DIR: fs.mkdtempSync(path.join(process.env.TMPDIR ?? '/tmp', 'ps-audit-')) }, { SESSION_SECRET: 'x'.repeat(48), STATE_SECRET: 'y'.repeat(48), PORT: '0' });
  if (cfg.limits.apiPerMinute > 0 && cfg.url.allowPrivate === false) info.push('SSRF : accès aux réseaux internes refusé par défaut ✔');
  else add('high', 'politique SSRF par défaut relâchée', 'src/config/env.js', 'URL_ALLOW_PRIVATE_HOSTS doit être faux par défaut.');
} catch (err) {
  info.push(`ACTION NON EXÉCUTÉE : garde-fous de configuration (RAISON : ${err.message})`);
}

/* ---- Docker -------------------------------------------------------------- */
for (const [file, checks] of [
  ['Dockerfile', [
    [/^FROM\s+\S+:latest/m, 'base d’image non épinglée (:latest)', 'Épingler une version mineure, ex. node:22.20-bookworm-slim.'],
    [/(?:^|\n)(?:COPY|ADD)\s+--from=.*\s+\.\/?$/m, null, null],
    [/\bcurl[^\n]*\|\s*(?:ba)?sh/, 'installation par pipe-to-shell', 'Télécharger, vérifier l’empreinte, puis installer.'],
  ]],
  ['docker-compose.yml', [
    [/cap_add:\s*\[[^\]]*(SYS_ADMIN|ALL)/i, 'capacités Linux trop larges', 'Retirer cap_add ; le service n’en a pas besoin.'],
    [/privileged:\s*true/i, 'mode privilégié', 'Passer privileged: false.'],
    [/(?:ports:\s*\n\s*-)\s*["']?0\.0\.0\.0:/, null, null],
  ]],
]) {
  const p = path.join(ROOT, file);
  if (!fs.existsSync(p)) {
    add('medium', `${file} absent`, file, 'Fournir un démarrage reproductible (Dockerfile + docker-compose.yml).');
    continue;
  }
  const text = fs.readFileSync(p, 'utf8');
  for (const [re, title, advice] of checks) {
    if (title && re.test(text)) add('high', `${file} : ${title}`, file, advice);
  }
  if (file === 'Dockerfile') {
    if (!/^USER\s+(?!root)\S+/m.test(text)) add('high', 'Dockerfile : exécution en root', 'Dockerfile', 'Créer un utilisateur dédié et le définir avant CMD.');
    else info.push('Dockerfile : exécution sous un utilisateur non root ✔');
    if (/^ENV\s+SESSION_SECRET/m.test(text)) add('critical', 'Dockerfile : secret embarqué dans l’image', 'Dockerfile', 'Injecter au runtime (secret Docker/volume), jamais via ENV.');
  }
  if (file === 'docker-compose.yml') {
    if (!/read_only:\s*true/.test(text)) info.push('note : le système de fichiers du service n’est pas en lecture seule (option durcie possible)');
    if (!/no-new-privileges/.test(text)) add('medium', 'docker-compose : no_new_privileges absent', 'docker-compose.yml', 'Ajouter security_opt: ["no-new-privileges:true"].');
  }
}

/* ---- dépendances --------------------------------------------------------- */
// lint-allow: `npm audit` en lecture seule, timeout dur, aucune interpolation utilisateur.
const npmAudit = spawnSync('npm', ['audit', '--json', '--omit=dev'], { cwd: ROOT, encoding: 'utf8', timeout: 45000 });
if (npmAudit.status === 0 || npmAudit.stdout.trim().startsWith('{')) {
  try {
    const parsed = JSON.parse(npmAudit.stdout || '{}');
    const v = parsed?.metadata?.vulnerabilities ?? {};
    const total = Object.entries(v).filter(([, n]) => n > 0).map(([k, n]) => `${n} ${k}`).join(', ');
    if (!Object.keys(v).length || Object.values(v).every((n) => !n)) info.push('npm audit (prod) : 0 vulnérabilité connue ✔');
    else add(v.high ? 'critical' : 'medium', `dépendances de production vulnérables : ${total}`, 'package.json', '`npm audit fix`, puis vérifier les avis non corrigibles.');
  } catch {
    info.push('ACTION NON EXÉCUTÉE : analyse npm audit (RAISON : sortie illisible)');
  }
} else {
  info.push('ACTION NON EXÉCUTÉE : analyse npm audit (RAISON : registre inatteignable depuis cet environnement)');
}

/* ---- sortie -------------------------------------------------------------- */
const order = { critical: 0, high: 1, medium: 2, low: 3 };
findings.sort((a, b) => (order[a.level] ?? 9) - (order[b.level] ?? 9));
const counts = findings.reduce((acc, f) => ({ ...acc, [f.level]: (acc[f.level] ?? 0) + 1 }), {});

if (ignoredHits) {
  info.push(`${ignoredHits} correspondance(s) de secret dans des fichiers ignorés par Git (locaux, non publiables) — valeur à ne jamais forcer dans l'index, rotation conseillée si elle a circulé.`);
}

if (asJson) {
  process.stdout.write(`${JSON.stringify({ ok: findings.length === 0, counts, findings, info, ignoredHits }, null, 2)}\n`);
} else {
  console.log('AUDIT DE SÉCURITÉ — PrinceNsamba AI');
  console.log(`  ${textFiles.length} fichiers passés en revue, ${findings.length} constat(s).`);
  if (!findings.length) console.log('\n  Aucun constat.\n  Points vérifiés :');
  else console.log('\n  CONSTATS :');
  for (const f of findings) console.log(`    [${f.level.toUpperCase().padEnd(6)}] ${f.title}\n             où : ${f.where}\n             action : ${f.advice}`);
  console.log('\n  VÉRIFICATIONS POSITIVES / RÉSERVES :');
  for (const i of info) console.log(`    · ${i}`);
  const prod = ['Dockerfile', 'docker-compose.yml', '.dockerignore', '.env.example', 'README.md'];
  console.log(`\n  Synthèse : ${JSON.stringify(counts)} ; fichiers de déploiement présents : ${prod.filter((p) => fs.existsSync(path.join(ROOT, p))).length}/${prod.length}.`);
  if (findings.some((f) => f.level === 'critical' || (strict && f.level === 'high'))) {
    console.log('  Statut : ÉCHEC.');
    process.exit(1);
  }
  console.log('  Statut : OK.');
}
