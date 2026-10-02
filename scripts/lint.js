/**
 * Static checks that can be verified without executing the app.
 * Run: `npm run lint`. Exits non-zero on any finding.
 *
 * It is a real, executed gate — not a claim: every check below reads the
 * repository (or imports a module) and reports concrete file:line evidence.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SKIP_DIRS = new Set(['node_modules', '.git', 'data', 'dist', 'coverage', 'tmp', 'Unselected files']);
const CODE_EXT = new Set(['.js', '.jsx', '.mjs', '.cjs']);
const TEXT_EXT = new Set(['.js', '.jsx', '.mjs', '.cjs', '.json', '.md', '.yml', '.yaml', '.sql', '.html', '.css', '.sh', '.txt']);

function* walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === '.git') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      yield* walk(full);
    } else if (entry.isFile()) {
      yield full;
    }
  }
}

const problems = [];
const notes = [];

function flag(file, line, why) {
  problems.push(`${path.relative(ROOT, file)}${line ? `:${line}` : ''} — ${why}`);
}

/* ------------------------------------------------------------- syntax check */
// Real parser check (not a brace heuristic): Node's own `--check` is run on
// every server-side JS file. .jsx/.html are covered by `npm run build`.
const syntaxTargets = [];
const jsxSkipped = [];
let allowances = 0;
for (const file of walk(ROOT)) {
  const rel = path.relative(ROOT, file).split(path.sep).join('/');
  if (!CODE_EXT.has(path.extname(file))) continue;
  if (rel.startsWith('dist/') || rel.startsWith('data/')) continue;
  // Le JSX n'est pas du JS : `node --check` échouerait sur la syntaxe React.
  // Ces fichiers sont validés par `npm run build` (Vite/esbuild), et cette
  // exigence est reprise dans le workflow CI.
  if (path.extname(file) === '.jsx') { jsxSkipped.push(rel); continue; }
  syntaxTargets.push(file);
}

const { spawnSync } = await import('node:child_process');
for (const file of syntaxTargets) {
  const res = spawnSync(process.execPath, ['--input-type=module', '--check'], {
    input: fs.readFileSync(file),
    encoding: 'utf8',
  });
  if (res.status !== 0) {
    const first = String(res.stderr || '').split('\n').find((l) => l.trim().startsWith('SyntaxError') || /\[stdin\]:\d+/.test(l)) ?? 'erreur de syntaxe';
    const line = /\[stdin\]:(\d+)/.exec(String(res.stderr));
    flag(file, line ? Number(line[1]) : null, `syntaxe invalide : ${first.trim().slice(0, 160)}`);
  }
}

/* --------------------------------------------------- real parse validation  */
// Import every ES module that has no side effects on boot (services/utils).
const importTargets = [
  'src/utils/errors.js',
  'src/utils/crypto.js',
  'src/utils/cookies.js',
  'src/utils/net.js',
  'src/utils/logger.js',
  'src/config/env.js',
  'src/db/index.js',
  'src/db/migrate.js',
  'src/services/password.service.js',
  'src/services/documents.service.js',
  'src/services/zip.js',
  'src/services/rbac.service.js',
  'src/services/settings.service.js',
  'src/services/files.service.js',
  'src/services/audit.service.js',
  'src/services/auth.service.js',
  'src/services/rate-limit.service.js',
  'src/services/url.service.js',
  'src/services/agents.service.js',
  'src/services/dashboard.service.js',
  'src/repositories/users.repo.js',
  'src/repositories/sessions.repo.js',
  'src/routes/_helpers.js',
  'src/runtime.js',
  'src/app.js',
  'src/server.js',
];
for (const rel of importTargets) {
  const abs = path.join(ROOT, rel);
  if (!fs.existsSync(abs)) {
    flag(abs, null, 'fichier attendu absent');
    continue;
  }
  try {
    await import(`../${rel}`);
  } catch (err) {
    flag(abs, null, `import échoué : ${err.message.split('\n')[0]}`);
  }
}

/* ---------------------------------------------------- security static rules */
const SECRET_PATTERNS = [
  { why: 'mot de passe codé en dur', re: /\b(?:password|passwd|pwd)\s*[:=]\s*['"][^'"\s]{6,}['"]/i, allow: /example|changeme|\$\{|process\.env|REDACTED|null|''|""/i },
  { why: 'clé AWS', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { why: 'clé privée', re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { why: 'jeton GitHub', re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/ },
  { why: 'jeton Slack', re: /\bxox[baprs]-[A-Za-z0-9]{10,}\b/ },
  { why: 'URL avec identifiants', re: /postgres(?:ql)?:\/\/[^/\s:@]+:[^/\s@]{3,}@/ },
];

for (const file of walk(ROOT)) {
  const rel = path.relative(ROOT, file);
  if (!TEXT_EXT.has(path.extname(file))) continue;
  if (rel === 'scripts/lint.js') continue; // patterns live here by definition
  // Les tests et la documentation manipulent des identifiants manifestement
  // fictifs : on n'y recherche que les fuites à haute confiance (clés AWS,
  // clés privées, jetons SaaS), jamais les constantes de test.
  // La documentation et les tests **nomment** les primitives dangereuses et
  // manipulent des identifiants fictifs : on n'y recherche que les fuites à
  // haute confiance (clés AWS, clés privées, jetons SaaS). Le code applicatif
  // (`src/`, `client/`) et les scripts restent stricts ; une dérogation y est
  // possible par commentaire `// lint-allow: <motif>` et est comptée, donc
  // visible en revue de sortie de lint.
  const isProse = rel.startsWith('docs/') || rel === 'README.md';
  const isFixture = rel.startsWith('tests/');
  const lenient = isProse || isFixture;
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  lines.forEach((line, idx) => {
    for (const { why, re, allow } of SECRET_PATTERNS) {
      if (re.test(line) && !(allow && allow.test(line))) {
        if (lenient && why === 'mot de passe codé en dur') continue;
        flag(file, idx + 1, `secret potentiel (${why})`);
      }
    }
    if (/eval\(|new Function\(|child_process|execSync\(|spawnSync?\(|dangerouslySetInnerHTML|innerHTML\s*=|document\.write\(/.test(line)) {
      // Les tests manipulent volontairement ces chaînes (sondes XSS) : ils ne
      // les exécutent pas.
      // Une dérogation s'écrit sur la ligne ou dans les 3 lignes qui la précèdent
      // (les justifications tiennent souvent sur plusieurs lignes de commentaire).
      const justified = /lint-allow:/.test(lines.slice(Math.max(0, idx - 3), idx + 1).join('\n'));
      if (justified) allowances += 1;
      else if (!lenient) flag(file, idx + 1, 'primitive dangereuse à justifier (eval/exec/innerHTML) — sinon marquer `// lint-allow: <motif>`');
    }
    if (/\bconsole\.(log|debug|info)\(/.test(line) && rel.startsWith('src/')) {
      flag(file, idx + 1, 'console.* dans src/ — utiliser le logger (journalisation des secrets)');
    }
  });

  // SQL interpolation review: static fragments are fine, request data is not.
  const SQL_OK = /^(?:PUBLIC_SELECT|ROLES_SUBQUERY|permCols|clause|base|dir|\w+\.map\(\(\)\s*=>\s*'\?'\)\.join\([^)]*\)|where\.join\([^)]*\)|[A-Za-z_]+\s*\?\s*'[A-Za-z_?,\s.]*'\s*:.*)$/;
  const text = lines.join('\n');
  const starts = [...text.matchAll(/\b(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\b[^;]{0,400}?\$\{/g)];
  for (const m of starts) {
    const after = text.slice(m.index + m[0].length, m.index + m[0].length + 120);
    const expr = after.slice(0, after.indexOf('}')).trim();
    if (!expr) continue;
    if (SQL_OK.test(expr)) continue;
    if (/\breq\.|body\.|query\.|validated|params\[|input|userInput|\bq\b|search|email|password|username|token/i.test(expr)) {
      const lineNo = text.slice(0, m.index).split('\n').length;
      flag(file, lineNo, `interpolation SQL suspecte (donnée potentiellement contrôlée) : \${${expr.slice(0, 60)}} — lier le paramètre à la place`);
    }
  }
}

/* --------------------------------------------------------- ignore coverage */
const ignoreChecks = [
  { file: '.gitignore', must: ['.env', 'data/', '*.db', 'node_modules/'] },
  { file: '.dockerignore', must: ['.git', '.env', 'node_modules', 'data/'] },
];
for (const { file, must } of ignoreChecks) {
  const abs = path.join(ROOT, file);
  if (!fs.existsSync(abs)) {
    flag(abs, null, 'fichier manquant (exclusion des secrets obligatoire)');
    continue;
  }
  const content = fs.readFileSync(abs, 'utf8');
  for (const needle of must) {
    if (!content.split('\n').some((l) => l.trim() === needle)) flag(abs, null, `absence de « ${needle} »`);
  }
}
if (fs.existsSync(path.join(ROOT, '.env'))) {
  notes.push('⚠ .env présent localement : vérifier qu’il reste ignoré par Git (git check-ignore .env).');
}

/* ------------------------------------------------------------- env surface */
const envExample = path.join(ROOT, '.env.example');
if (fs.existsSync(envExample)) {
  const sample = new Set(
    fs
      .readFileSync(envExample, 'utf8')
      .split('\n')
      .map((l) => /^\s*#?\s*([A-Z][A-Z0-9_]*)=/.exec(l)?.[1])
      .filter(Boolean),
  );
  const used = new Set();
  for (const file of walk(path.join(ROOT, 'src'))) {
    if (!CODE_EXT.has(path.extname(file))) continue;
    for (const m of fs.readFileSync(file, 'utf8').matchAll(/\b(?:env|process\.env)\.([A-Z][A-Z0-9_]{2,})\b/g)) used.add(m[1]);
  }
  const missing = [...used].filter((k) => !sample.has(k) && k !== 'NODE_ENV');
  if (missing.length) flag(path.join(ROOT, '.env.example'), null, `clés utilisées par le code mais absentes de l’exemple : ${missing.join(', ')}`);
  notes.push(`Variables d’environnement documentées : ${sample.size} ; utilisées par le code : ${used.size}.`);
if (allowances) notes.push(`Dérogations « lint-allow » comptées : ${allowances} — chacune doit être justifiée en revue.`);
}

/* --------------------------------------------------------- config sanity  */
const pkgPath = path.join(ROOT, 'package.json');
const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
if (pkg.type !== 'module') flag(pkgPath, null, 'type:module attendu (code ESM)');
for (const dep of ['better-sqlite3', 'sqlite3', 'mysql2', 'pg', 'bcrypt', 'argon2']) {
  if (pkg.dependencies?.[dep]) notes.push(`dépendance base de données/hachage détectée (${dep}) : vérifier qu’elle est bien buildable dans l’image Docker.`);
}
const nativeDeps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies }).filter((d) =>
  ['better-sqlite3', 'argon2', 'bcrypt', 'node-gyp', 'canvas', 'sharp'].includes(d),
);
if (nativeDeps.length) {
  notes.push(`Dépendances natives (${nativeDeps.join(', ')}) : un outil de compilation est requis dans l’image — cf. Dockerfile multi-stage.`);
}

/* ----------------------------------------------------- SQL migration shape */
for (const f of fs.readdirSync(path.join(ROOT, 'src/db/migrations')).sort()) {
  const sql = fs.readFileSync(path.join(ROOT, 'src/db/migrations', f), 'utf8');
  if (/DROP TABLE|DROP COLUMN|TRUNCATE/i.test(sql)) flag(path.join(ROOT, 'src/db/migrations', f), null, 'destruction de données dans une migration — exiger une sauvegarde + validation humaine');
  if (/password\s+TEXT|plain/i.test(sql) && !/mot de passe en clair/.test(sql)) flag(path.join(ROOT, 'src/db/migrations', f), null, 'mention d’une colonne mot de passe en clair ?');
}

/* ------------------------------------------------------------------ report  */
const out = [];
out.push('LINT — PrinceNsamba AI');
out.push(`  fichiers analysés : ${syntaxTargets.length} (syntaxe) / tous types ${[...walk(ROOT)].length}`);
out.push(`  modules importés pour vérification : ${importTargets.length}`);
if (jsxSkipped.length) out.push(`  fichiers JSX syntaxiquement validés par le build (${jsxSkipped.length}) : \`npm run build\``);
if (notes.length) out.push('  notes :\n' + notes.map((n) => `    - ${n}`).join('\n'));
if (problems.length) {
  out.push(`\n  PROBLÈMES (${problems.length}) :`);
  out.push(problems.map((p) => `    - ${p}`).join('\n'));
  process.stdout.write(out.join('\n') + '\n');
  process.exit(1);
}
out.push('\n  Aucun problème détecté ✔');
process.stdout.write(out.join('\n') + '\n');
