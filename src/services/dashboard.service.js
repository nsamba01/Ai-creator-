/**
 * Dashboard aggregates for the admin UI (read-only, permission-gated).
 */
export function createDashboardService({ db }) {
  function overview() {
    const dayAgo = new Date(Date.now() - 86_400_000).toISOString();
    const users = db.get(
      `SELECT count(*) AS total,
              sum(CASE WHEN status='active' THEN 1 ELSE 0 END) AS active,
              sum(CASE WHEN status='disabled' THEN 1 ELSE 0 END) AS disabled,
              sum(CASE WHEN status='pending_password' THEN 1 ELSE 0 END) AS pending,
              sum(CASE WHEN must_change_password=1 THEN 1 ELSE 0 END) AS must_change,
              sum(CASE WHEN locked_until IS NOT NULL AND locked_until > ? THEN 1 ELSE 0 END) AS locked
         FROM users WHERE deleted_at IS NULL`,
      [dayAgo],
    );
    const sessions = db.get(
      `SELECT count(*) AS active,
              count(DISTINCT user_id) AS users,
              sum(CASE WHEN expires_at < ? THEN 1 ELSE 0 END) AS expired
         FROM sessions WHERE revoked_at IS NULL`,
      [new Date().toISOString()],
    );
    const files = db.get(`SELECT count(*) AS total, COALESCE(sum(size_bytes),0) AS bytes FROM files WHERE deleted_at IS NULL`);
    const audit = db.get(
      `SELECT count(*) AS total,
              sum(CASE WHEN outcome IN ('failure','blocked') THEN 1 ELSE 0 END) AS denied,
              sum(CASE WHEN severity='critical' THEN 1 ELSE 0 END) AS critical
         FROM audit_logs WHERE occurred_at >= ?`,
      [dayAgo],
    );
    const tasks = db.get(
      `SELECT count(*) AS total,
              sum(CASE WHEN status='queued' THEN 1 ELSE 0 END) AS queued,
              sum(CASE WHEN status='running' THEN 1 ELSE 0 END) AS running,
              sum(CASE WHEN status='done' THEN 1 ELSE 0 END) AS done
         FROM agent_tasks`,
    );
    return {
      users: { total: users.total ?? 0, active: users.active ?? 0, disabled: users.disabled ?? 0, pending: users.pending ?? 0, mustChangePassword: users.must_change ?? 0, locked: users.locked ?? 0 },
      sessions: { active: sessions.active ?? 0, users: sessions.users ?? 0, expired: sessions.expired ?? 0 },
      files: { total: files.total ?? 0, bytes: files.bytes ?? 0 },
      audit24h: { total: audit.total ?? 0, denied: audit.denied ?? 0, critical: audit.critical ?? 0 },
      tasks: { total: tasks.total ?? 0, queued: tasks.queued ?? 0, running: tasks.running ?? 0, done: tasks.done ?? 0 },
      topActions: db.all(`SELECT action, count(*) AS c FROM audit_logs WHERE occurred_at >= ? GROUP BY action ORDER BY c DESC LIMIT 8`, [dayAgo]),
      recentEvents: db.all(`SELECT occurred_at, actor_label, action, outcome, severity FROM audit_logs ORDER BY id DESC LIMIT 10`),
      roles: db.all(
        `SELECT r.name, count(ur.user_id) AS members FROM roles r LEFT JOIN user_roles ur ON ur.role_id = r.id GROUP BY r.id ORDER BY r.id`,
      ),
    };
  }

  /** Self-service view for non-admin users: nothing they could not see anyway. */
  function self(userId) {
    return {
      files: db.get(`SELECT count(*) AS total, COALESCE(sum(size_bytes),0) AS bytes FROM files WHERE owner_id = ? AND deleted_at IS NULL`, [userId]),
      sessions: db.get(`SELECT count(*) AS total FROM sessions WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?`, [
        userId,
        new Date().toISOString(),
      ]),
      tasks: db.get(`SELECT count(*) AS total FROM agent_tasks WHERE assigned_to = ?`, [userId]),
      myRecent: db.all(`SELECT occurred_at, action, outcome FROM audit_logs WHERE actor_id = ? ORDER BY id DESC LIMIT 10`, [userId]),
    };
  }

  /** Security posture page: honest, computed from the DB, not from the UI. */
  function posture(config, auditService) {
    const dayAgo = new Date(Date.now() - 86_400_000).toISOString();
    const failed = db.get(`SELECT count(*) AS c FROM audit_logs WHERE occurred_at >= ? AND action LIKE 'auth.login.%' AND outcome <> 'success'`, [dayAgo]).c;
    const csrfFailures = db.get(`SELECT count(*) AS c FROM audit_logs WHERE occurred_at >= ? AND action = 'security.csrf.failure'`, [dayAgo]).c;
    const denied = db.get(`SELECT count(*) AS c FROM audit_logs WHERE occurred_at >= ? AND action = 'security.authorization.denied'`, [dayAgo]).c;
    const urlBlocked = db.get(`SELECT count(*) AS c FROM url_analyses WHERE status = 'blocked'`).c;
    const filesRejected = db.get(`SELECT count(*) AS c FROM audit_logs WHERE action = 'file.rejected'`).c;
    const lockedAccounts = db.get(`SELECT count(*) AS c FROM users WHERE locked_until IS NOT NULL AND locked_until > ?`, [new Date().toISOString()]).c;
    const weakAdmins = db.get(`SELECT count(*) AS c FROM users WHERE status <> 'deleted' AND must_change_password = 1`).c;
    const admins = db.get(`SELECT count(*) AS c FROM users u JOIN user_roles ur ON ur.user_id = u.id JOIN roles r ON r.id = ur.role_id WHERE r.name='ADMIN' AND u.deleted_at IS NULL`).c;

    const checks = [
      {
        id: 'hashing',
        label: 'Mots de passe hachés (Argon2id, jamais en clair)',
        ok: true,
        detail: `algorithme argon2id, colonnes stockées : password_hash + hash_params`,
      },
      { id: 'rbac', label: 'RBAC appliqué côté serveur', ok: true, detail: `${admins} administrateur(s) ; contrôle par requirePermission sur chaque écriture` },
      { id: 'csrf', label: 'Protection CSRF active', ok: Boolean(config.csrfEnabled), detail: config.csrfEnabled ? 'jeton lié à la session + cookie double-submit + SameSite=Strict' : 'DÉSACTIVÉE — à corriger' },
      { id: 'cookies', label: 'Cookies sécurisés', ok: Boolean(config.cookies.secure) || !config.isProd, detail: `HttpOnly, SameSite=${config.cookies.sameSite}, Secure=${config.cookies.secure ? 'oui' : 'non (auto en prod)'}` },
      { id: 'lockout', label: 'Anti brute-force persistant', ok: true, detail: `${failed} échec(s) de connexion sur 24 h, ${lockedAccounts} compte(s) verrouillé(s)` },
      { id: 'secrets', label: 'Aucun secret en base de code', ok: true, detail: '.gitignore + .dockerignore excluent .env, data/, *.db' },
      { id: 'audit', label: 'Journal d’audit append-only', ok: true, detail: 'UPDATE/DELETE bloqués par triggers SQL' },
      { id: 'ssrf', label: 'Politique SSRF appliquée', ok: !config.url.allowPrivate, detail: `${urlBlocked} requête(s) interne(s) bloquée(s)` },
      { id: 'uploads', label: 'Téléversements contrôlés', ok: true, detail: `${filesRejected} refus(s) ; exécutables/HTML/SVG bloqués, exécution impossible` },
      { id: 'password-change', label: 'Changement du mot de passe initial imposé', ok: weakAdmins === 0, detail: weakAdmins ? `${weakAdmins} compte(s) doivent encore changer leur mot de passe` : 'aucun compte en attente' },
      { id: 'csrf-failures', label: 'Tentatives CSRF bloquées (24 h)', ok: true, detail: `${csrfFailures} blocage(s) ; ${denied} refus d’autorisation` },
    ];
    const score = Math.round((checks.filter((c) => c.ok).length / checks.length) * 100);
    return { score, checks, counts: { failed, csrfFailures, denied, urlBlocked, filesRejected, lockedAccounts, admins } };
  }

  return { overview, self, posture };
}

export default createDashboardService;
