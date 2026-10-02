-- ===========================================================================
-- PrinceNsamba AI - 001_init.sql
-- Schéma de base : identités, RBAC, sessions, tokens, audit, fichiers,
-- configuration, agents/tâches.
--
-- Conventions :
--   * timestamps TEXT ISO-8601 UTC (comparables lexicographiquement)
--   * aucun mot de passe en clair : uniquement `password_hash` (Argon2id PHC)
--   * aucun token sensible en clair : uniquement des empreintes HMAC-SHA256
--   * suppression logique (deleted_at) sur les entités métier
-- ===========================================================================

CREATE TABLE IF NOT EXISTS users (
  id                     INTEGER PRIMARY KEY,
  email                  TEXT    NOT NULL UNIQUE,
  username               TEXT    NOT NULL UNIQUE,
  display_name           TEXT    NOT NULL DEFAULT '',
  password_hash          TEXT    NOT NULL,
  hash_params            TEXT    NOT NULL DEFAULT '{}',
  status                 TEXT    NOT NULL DEFAULT 'active'
                           CHECK (status IN ('pending_password','active','disabled','deleted')),
  must_change_password   INTEGER NOT NULL DEFAULT 1 CHECK (must_change_password IN (0,1)),
  failed_login_attempts  INTEGER NOT NULL DEFAULT 0,
  locked_until           TEXT,
  last_login_at          TEXT,
  password_changed_at    TEXT,
  created_at             TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at             TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  created_by             INTEGER REFERENCES users(id) ON DELETE SET NULL,
  deleted_at             TEXT
);
CREATE INDEX IF NOT EXISTS idx_users_email       ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username    ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_status      ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_locked      ON users(locked_until);

CREATE TABLE IF NOT EXISTS roles (
  id          INTEGER PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
  description TEXT NOT NULL DEFAULT '',
  is_system   INTEGER NOT NULL DEFAULT 0 CHECK (is_system IN (0,1)),
  created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS permissions (
  id          INTEGER PRIMARY KEY,
  key         TEXT NOT NULL UNIQUE,
  category    TEXT NOT NULL DEFAULT 'general',
  description TEXT NOT NULL DEFAULT '',
  is_dangerous INTEGER NOT NULL DEFAULT 0 CHECK (is_dangerous IN (0,1)),
  created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_permissions_category ON permissions(category);

CREATE TABLE IF NOT EXISTS user_roles (
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id     INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  assigned_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  assigned_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  PRIMARY KEY (user_id, role_id)
);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id);

CREATE TABLE IF NOT EXISTS role_permissions (
  role_id       INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  granted_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  PRIMARY KEY (role_id, permission_id)
);
CREATE INDEX IF NOT EXISTS idx_role_permissions_perm ON role_permissions(permission_id);

-- Sessions applicatives. `token_hash` est un HMAC-SHA256 : une fuite de la
-- base ne permet pas de rejouer une session.
CREATE TABLE IF NOT EXISTS sessions (
  id            TEXT PRIMARY KEY,
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash    TEXT NOT NULL UNIQUE,
  csrf_token    TEXT NOT NULL,
  ip_hash       TEXT,
  user_agent_hash TEXT,
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  last_seen_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  expires_at    TEXT NOT NULL,
  revoked_at    TEXT,
  revoke_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_active  ON sessions(revoked_at, expires_at);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id           INTEGER PRIMARY KEY,
  user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  family_id    TEXT NOT NULL,
  token_hash   TEXT NOT NULL UNIQUE,
  issued_for_session TEXT REFERENCES sessions(id) ON DELETE SET NULL,
  created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  expires_at   TEXT NOT NULL,
  revoked_at   TEXT,
  replaced_by  INTEGER REFERENCES refresh_tokens(id) ON DELETE SET NULL,
  used_at      TEXT
);
CREATE INDEX IF NOT EXISTS idx_refresh_user   ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens(family_id);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id         INTEGER PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  purpose    TEXT NOT NULL DEFAULT 'reset' CHECK (purpose IN ('reset','invite','mfa')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  expires_at TEXT NOT NULL,
  used_at    TEXT,
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_purpose_tokens_user ON password_reset_tokens(user_id);

-- Journal d'audit : append-only (les triggers ci-dessous bloquent
-- UPDATE/DELETE, même pour un compte avec tous les droits SQL).
CREATE TABLE IF NOT EXISTS audit_logs (
  id            INTEGER PRIMARY KEY,
  occurred_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  actor_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
  actor_label   TEXT NOT NULL DEFAULT 'anonymous',
  action        TEXT NOT NULL,
  category      TEXT NOT NULL DEFAULT 'auth',
  target_type   TEXT,
  target_id     TEXT,
  outcome       TEXT NOT NULL DEFAULT 'success' CHECK (outcome IN ('success','failure','blocked','error')),
  severity      TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('debug','info','notice','warning','critical')),
  ip_hash       TEXT,
  user_agent_hash TEXT,
  request_id    TEXT,
  detail_json   TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_occurred ON audit_logs(occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_actor    ON audit_logs(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_action   ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_logs(severity, occurred_at);

CREATE TRIGGER IF NOT EXISTS audit_logs_no_update
BEFORE UPDATE ON audit_logs
BEGIN
  SELECT RAISE(ABORT, 'audit_logs est un journal append-only : modification interdite');
END;

CREATE TRIGGER IF NOT EXISTS audit_logs_no_delete
BEFORE DELETE ON audit_logs
BEGIN
  SELECT RAISE(ABORT, 'audit_logs est un journal append-only : suppression interdite');
END;

-- Anti brute-force persistant (survit aux redémarrages).
CREATE TABLE IF NOT EXISTS login_attempts (
  bucket_key   TEXT PRIMARY KEY,
  count        INTEGER NOT NULL DEFAULT 0,
  first_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  last_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  locked_until TEXT,
  revised_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Fichiers téléversés : le nom physique est un UUID, jamais le nom fourni.
CREATE TABLE IF NOT EXISTS files (
  id            INTEGER PRIMARY KEY,
  owner_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  original_name TEXT NOT NULL,
  stored_name   TEXT NOT NULL UNIQUE,
  relative_path TEXT NOT NULL,
  mime_type     TEXT NOT NULL DEFAULT 'application/octet-stream',
  extension     TEXT NOT NULL DEFAULT '',
  size_bytes    INTEGER NOT NULL,
  sha256        TEXT NOT NULL,
  kind          TEXT NOT NULL DEFAULT 'other',
  magic_ok      INTEGER NOT NULL DEFAULT 1 CHECK (magic_ok IN (0,1)),
  scan_status   TEXT NOT NULL DEFAULT 'checked' CHECK (scan_status IN ('pending','checked','rejected')),
  scan_notes    TEXT,
  download_count INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  deleted_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_files_owner   ON files(owner_id);
CREATE INDEX IF NOT EXISTS idx_files_sha256  ON files(sha256);
CREATE INDEX IF NOT EXISTS idx_files_created ON files(created_at);

CREATE TABLE IF NOT EXISTS document_analyses (
  id          INTEGER PRIMARY KEY,
  file_id     INTEGER REFERENCES files(id) ON DELETE CASCADE,
  requested_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  source      TEXT NOT NULL DEFAULT 'upload' CHECK (source IN ('upload','url','inline')),
  extension   TEXT NOT NULL DEFAULT '',
  status      TEXT NOT NULL DEFAULT 'ok' CHECK (status IN ('ok','partial','failed')),
  summary     TEXT NOT NULL DEFAULT '',
  metrics_json TEXT,
  findings_json TEXT,
  created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_doc_created ON document_analyses(created_at);

CREATE TABLE IF NOT EXISTS url_analyses (
  id           INTEGER PRIMARY KEY,
  requested_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  host         TEXT NOT NULL,
  scheme       TEXT NOT NULL,
  status       TEXT NOT NULL CHECK (status IN ('ok','redirected','blocked','error')),
  reason       TEXT,
  final_host   TEXT,
  http_status  INTEGER,
  bytes        INTEGER,
  title        TEXT,
  metrics_json TEXT,
  created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_url_created ON url_analyses(created_at);

CREATE TABLE IF NOT EXISTS settings (
  key        TEXT PRIMARY KEY,
  value_json TEXT NOT NULL,
  value_type TEXT NOT NULL DEFAULT 'string' CHECK (value_type IN ('string','int','bool','json','secret')),
  min_value  INTEGER,
  max_value  INTEGER,
  description TEXT NOT NULL DEFAULT '',
  is_public  INTEGER NOT NULL DEFAULT 0 CHECK (is_public IN (0,1)),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL
);

-- Tableau de bord des agents orchestrés (CODAGE/TESTS/SECURITE/...).
CREATE TABLE IF NOT EXISTS agent_tasks (
  id          INTEGER PRIMARY KEY,
  ref         TEXT NOT NULL UNIQUE,
  title       TEXT NOT NULL,
  agent_role  TEXT NOT NULL CHECK (agent_role IN ('architecte','developpeur','qa','securite','reviewer','integrateur','video','document')),
  status      TEXT NOT NULL DEFAULT 'queued'
                CHECK (status IN ('queued','running','blocked','review','done','failed','cancelled')),
  priority    TEXT NOT NULL DEFAULT 'normal' CHECK (priority IN ('low','normal','high','critical')),
  description TEXT NOT NULL DEFAULT '',
  result_summary TEXT NOT NULL DEFAULT '',
  required_permission TEXT,
  created_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
  assigned_to INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON agent_tasks(status, priority);
