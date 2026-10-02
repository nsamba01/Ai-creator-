#!/usr/bin/env node
/**
 * Create (or repair) the first administrator from the environment.
 *
 * Usage:
 *   node scripts/bootstrap-admin.js --email admin@corp.tld [--username admin]
 *       [--generate] [--rotate]
 *
 * Never put a password on the command line in a shared shell: use
 * BOOTSTRAP_ADMIN_PASSWORD in the environment, or --generate which writes the
 * secret to `data/bootstrap-admin-password` (0600) and prints only the path.
 */
import { loadConfig } from '../src/config/env.js';
import { loadDotenv } from '../src/config/dotenv.js';
import { createRuntime } from '../src/runtime.js';
import { bootstrapAdmin } from '../src/services/bootstrap.service.js';
import { hashPassword, assertPasswordPolicy } from '../src/services/password.service.js';
import * as usersRepo from '../src/repositories/users.repo.js';
import { randomTempPassword } from '../src/utils/crypto.js';
import fs from 'node:fs';

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--email') out.email = argv[++i];
    else if (a === '--username') out.username = argv[++i];
    else if (a === '--from-env') out.fromEnv = true;
    else if (a === '--password-file') out.passwordFile = argv[++i];
    else if (a === '--generate') out.generate = true;
    else if (a === '--rotate') out.rotate = true;
    else if (a === '--help' || a === '-h') out.help = true;
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));

if (args.help) {
  process.stdout.write(
    `Usage: node scripts/bootstrap-admin.js [options]

  --email <email>      adresse du compte administrateur
  --username <nom>     identifiant (défaut: admin)
  --generate           génère un mot de passe fort dans data/bootstrap-admin-password
  --from-env           exige BOOTSTRAP_ADMIN_PASSWORD (jamais en ligne de commande)
  --password-file <p>  lit le mot de passe dans un fichier (0600 recommandé)
  --rotate             régénère le mot de passe d'un ADMIN existant
  --help               cette aide
`,
  );
  process.exit(0);
}

loadDotenv({ root: process.cwd() });
const config = loadConfig();
const runtime = createRuntime({ config });
const { db, rbac } = runtime;

try {
  if (args.rotate) {
    const admin = db.get(
      `SELECT u.id, u.email FROM users u JOIN user_roles ur ON ur.user_id=u.id JOIN roles r ON r.id=ur.role_id
        WHERE r.name='ADMIN' AND u.deleted_at IS NULL ORDER BY u.id LIMIT 1`,
    );
    if (!admin) {
      process.stderr.write('Aucun administrateur existant.\n');
      process.exit(2);
    }
    const pwd = randomTempPassword(20);
    assertPasswordPolicy(pwd, { minLength: 12 });
    const { hash, params } = await hashPassword(pwd, config.password.argon2);
    usersRepo.updatePassword(db, admin.id, { passwordHash: hash, hashParams: params, clearMustChange: false });
    db.run(`UPDATE users SET must_change_password = 1, failed_login_attempts = 0, locked_until = NULL WHERE id = ?`, [admin.id]);
    db.run(`UPDATE sessions SET revoked_at = ?, revoke_reason = 'admin_password_rotated' WHERE user_id = ? AND revoked_at IS NULL`, [
      new Date().toISOString(),
      admin.id,
    ]);
    const file = config.bootstrapAdmin.passwordFile;
    fs.mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(file, `${pwd}\n`, { mode: 0o600 });
    runtime.audit.record({
      action: 'admin.password.rotated',
      category: 'admin',
      severity: 'critical',
      target_type: 'user',
      target_id: admin.id,
      detail: { method: 'script bootstrap-admin --rotate' },
    });
    process.stdout.write(`Mot de passe régénéré pour ${admin.email}\nÉcrit (0600) dans : ${file}\nSessions révoquées. À changer à la première connexion.\n`);
    process.exit(0);
  }

  const email = (args.email ?? config.bootstrapAdmin.email ?? 'admin@localhost.local').toLowerCase();
  const username = args.username ?? config.bootstrapAdmin.username ?? 'admin';
  const provided = config.bootstrapAdmin.password;
  let password = provided || null;
  let source = provided ? 'environnement' : null;
  let generated = false;
  if (args.fromEnv && !password) {
    process.stderr.write('BOOTSTRAP_ADMIN_PASSWORD est vide : renseignez-le, ou utilisez --password-file, ou laissez le script générer un mot de passe temporaire.\n');
    process.exit(2);
  }
  if (args.passwordFile) {
    // Le fichier est lu, jamais affiché. Un lien symbolique ou un fichier suspect est refusé :
    // ce script tourne souvent avec les droits du volume de données.
    let stat = null;
    try {
      stat = fs.lstatSync(args.passwordFile);
    } catch {
      process.stderr.write(`Impossible de lire ${args.passwordFile} (chemin inexistant ou illisible).\n`);
      process.exit(2);
    }
    if (stat.isSymbolicLink() || !stat.isFile() || stat.size > 4096) {
      process.stderr.write(`${args.passwordFile} refusé : ni lien symbolique, ni répertoire, ni fichier de plus de 4096 octets.\n`);
      process.exit(2);
    }
    password = fs.readFileSync(args.passwordFile, 'utf8').replace(/\r?\n$/, '');
    source = 'fichier';
    if (!password) {
      process.stderr.write(`${args.passwordFile} est vide.\n`);
      process.exit(2);
    }
  }
  if (!password) {
    password = randomTempPassword(20);
    generated = true;
  }

  const existing = usersRepo.findUserByIdentifier(db, email);
  if (existing && !args.generate) {
    process.stdout.write(`Utilisateur ${email} déjà présent — rien à créer. Utilisez --rotate pour changer son mot de passe.\n`);
    process.exit(0);
  }

  assertPasswordPolicy(password, { minLength: Math.max(12, config.password.minLength), context: [email, username] });
  const { hash, params } = await hashPassword(password, config.password.argon2);

  const created = db.tx(() => {
    const u =
      existing ??
      usersRepo.createUser(db, {
        email,
        username,
        displayName: 'Administrateur',
        passwordHash: hash,
        hashParams: params,
        mustChangePassword: true,
        status: 'active',
      });
    rbac.assignRoles({ actorUserId: u.id, userId: u.id, roleNames: ['ADMIN'] });
    return u;
  });
  rbac.invalidate(created.id);

  runtime.audit.record({
    action: 'admin.bootstrap.script',
    category: 'admin',
    severity: 'critical',
    target_type: 'user',
    target_id: created.id,
    detail: { email, passwordSource: generated ? 'généré' : source },
  });

  if (generated) {
    const file = config.bootstrapAdmin.passwordFile;
    fs.mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(file, `${password}\n`, { mode: 0o600 });
    process.stdout.write(
      `Administrateur créé : ${created.email} (${created.username})\n` +
        `Rôle : ADMIN — changement du mot de passe imposé à la première connexion.\n` +
        `Mot de passe temporaire écrit (0600) dans : ${file}\n`,
    );
  } else {
    process.stdout.write(
      `Administrateur créé : ${created.email} (${created.username}) avec le mot de passe fourni (${source}).\n` +
        `Changement du mot de passe imposé à la première connexion.\n` +
        (args.passwordFile ? `Pensez à supprimer ${args.passwordFile} après usage.\n` : ''),
    );
  }
} finally {
  runtime.close();
}
