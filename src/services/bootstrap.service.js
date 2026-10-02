/**
 * First-administrator bootstrap.
 *
 * The project rule is: initial credentials must come from OUTSIDE the source
 * tree. Implementation:
 *  - if BOOTSTRAP_ADMIN_PASSWORD is provided in the environment, it is used;
 *  - otherwise a strong random password is generated ONCE and written to
 *    `data/bootstrap-admin-password` with mode 0600. It is never printed to
 *    stdout, never returned by an API, and never stored in the audit log.
 *  - the account is created with `must_change_password = 1`, so the initial
 *    secret is unusable after the first login.
 * Idempotent: a second run never resets an existing administrator.
 */
import fs from 'node:fs';
import path from 'node:path';
import { hashPassword } from './password.service.js';
import { randomTempPassword } from '../utils/crypto.js';
import { logger } from '../utils/logger.js';
import * as usersRepo from '../repositories/users.repo.js';

export async function bootstrapAdmin({ db, config, audit, rbac }) {
  const opts = config.bootstrapAdmin;
  const result = { created: false, reason: '', email: opts.email || null, credentialsFile: null };

  if (!opts.enabled) {
    result.reason = 'BOOTSTRAP_ADMIN=0 : création automatique désactivée.';
    return result;
  }
  const admins = usersRepo.countAdmins(db);
  if (admins > 0) {
    result.reason = `${admins} administrateur(s) déjà présent(s) : rien à faire.`;
    return result;
  }

  const email = opts.email || 'admin@localhost.local';
  const username = opts.username || 'admin';
  let password = opts.password || '';
  let generated = false;
  let credentialsFile = null;

  if (!password) {
    password = randomTempPassword(20);
    generated = true;
    credentialsFile = opts.passwordFile;
    try {
      fs.mkdirSync(path.dirname(credentialsFile), { recursive: true, mode: 0o700 });
      fs.writeFileSync(credentialsFile, `${password}\n`, { mode: 0o600, flag: 'wx' });
    } catch (err) {
      if (err.code === 'EEXIST') {
        // The file exists from a previous run: reuse it, never overwrite.
        password = fs.readFileSync(credentialsFile, 'utf8').trim() || password;
      } else {
        logger.warn('écriture du fichier d’identifiants impossible — mot de passe usable une seule fois via l’environnement', {
          error: err.message,
        });
        credentialsFile = null;
      }
    }
  }

  const { hash, params } = await hashPassword(password, config.password.argon2);
  const user = usersRepo.createUser(db, {
    email,
    username,
    displayName: 'Administrateur',
    passwordHash: hash,
    hashParams: params,
    mustChangePassword: true,
    status: 'active',
  });
  rbac.assignRoles({ actorUserId: user.id, userId: user.id, roleNames: ['ADMIN'] });
  rbac.invalidate(user.id);

  audit?.record({
    action: 'admin.bootstrap',
    category: 'admin',
    actor: { id: user.id, email },
    target_type: 'user',
    target_id: user.id,
    severity: 'critical',
    detail: { passwordSource: generated ? 'généré et stocké dans le volume' : 'fourni par variable d’environnement', mustChangePassword: true },
  });

  logger.warn(
    generated
      ? `Compte administrateur initial créé. Mot de passe temporaire écrit dans ${credentialsFile ?? 'le volume (non persisté)'} — à changer à la première connexion.`
      : 'Compte administrateur initial créé depuis l’environnement — mot de passe à changer à la première connexion.',
  );

  return { ...result, created: true, reason: 'administrateur initial créé', userId: user.id, credentialsFile, mustChangePassword: true };
}

export default bootstrapAdmin;
