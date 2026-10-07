-- ===========================================================================
-- PrinceNsamba AI - 002_seed_rbac.sql
-- Référentiel RBAC : permissions granulaires, rôles ADMIN / USER, matrice.
--
-- Principe de moindre privilège :
--   * USER ne reçoit AUCUNE permission de gestion des utilisateurs ;
--   * le contrôle est effectué côté serveur (requirePermission), jamais en
--     se fiant à ce que l'interface affiche.
-- ===========================================================================

INSERT OR IGNORE INTO permissions (key, category, description, is_dangerous) VALUES
  ('admin:access',        'admin',      'Accès au périmètre d''administration', 0),
  ('dashboard:read',      'admin',      'Lecture des indicateurs du tableau de bord', 0),
  ('users:read',          'users',      'Consulter la liste et le détail des utilisateurs', 0),
  ('users:create',        'users',      'Créer un utilisateur', 1),
  ('users:update',        'users',      'Modifier un utilisateur (profil, rôles)', 1),
  ('users:disable',       'users',      'Désactiver / réactiver un utilisateur', 1),
  ('users:delete',        'users',      'Supprimer (logiquement) un utilisateur', 1),
  ('users:reset_password', 'users',     'Réinitialiser l''accès d''un utilisateur', 1),
  ('roles:read',          'rbac',       'Consulter rôles et permissions', 0),
  ('roles:create',        'rbac',       'Créer un rôle', 1),
  ('roles:update',        'rbac',       'Modifier les permissions d''un rôle', 1),
  ('roles:delete',        'rbac',       'Supprimer un rôle non système', 1),
  ('sessions:read:any',   'security',   'Consulter toutes les sessions actives', 0),
  ('sessions:revoke:any', 'security',   'Révoquer la session d''un autre utilisateur', 1),
  ('audit:read',          'security',   'Consulter le journal d''audit', 0),
  ('audit:export',        'security',   'Exporter le journal d''audit', 1),
  ('settings:read',       'config',     'Lire la configuration autorisée', 0),
  ('settings:update',     'config',     'Modifier la configuration autorisée', 1),
  ('files:create',        'files',      'Téléverser des fichiers', 0),
  ('files:read',          'files',      'Lire les métadonnées de tous les fichiers', 0),
  ('files:read:any',      'files',      'Télécharger le fichier d''un autre utilisateur', 1),
  ('files:delete:any',    'files',      'Supprimer le fichier d''un autre utilisateur', 1),
  ('documents:analyze',   'agents',     'Analyser des documents (PDF/DOCX/XLSX/CSV...)', 0),
  ('urls:analyze',        'agents',     'Analyser une URL distante', 0),
  ('agents:read',         'agents',     'Consulter les agents et leurs tâches', 0),
  ('agents:update',       'agents',     'Piloter les tâches des agents', 1),
  ('security:read',       'security',   'Consulter l''état de sécurité et les blocages', 0);

-- Rôles système
INSERT OR IGNORE INTO roles (name, description, is_system) VALUES
  ('ADMIN', 'Administrateur : gestion complète des utilisateurs, rôles, configuration, audit et sécurité.', 1),
  ('USER',  'Utilisateur standard : fonctionnalités autorisées, aucune gestion des utilisateurs.', 1);

-- ADMIN : toutes les permissions (y compris les plus dangereuses)
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'ADMIN';

-- USER : uniquement l'auto-service. Aucune permission users:*, roles:*,
-- settings:*, audit:*, files:read:any, sessions:revoke:any.
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.key IN (
  'dashboard:read',
  'files:create',
  'files:read',
  'documents:analyze',
  'urls:analyze',
  'agents:read'
)
WHERE r.name = 'USER';

-- Configuration par défaut (modifiable uniquement par settings:update)
INSERT OR IGNORE INTO settings (key, value_json, value_type, min_value, max_value, description, is_public) VALUES
  ('security.session_ttl_minutes',    '60',    'int',  5,   43200, 'Durée de vie maximale d''une session (minutes)', 0),
  ('security.login_max_attempts',     '5',     'int',  3,   100,   'Tentatives de connexion avant verrouillage',     0),
  ('security.lockout_minutes',        '30',    'int',  1,   1440,  'Durée du verrouillage compte',                   0),
  ('security.password_min_length',    '12',    'int',  8,   128,   'Longueur minimale du mot de passe',              1),
  ('security.require_admin_mfa_hint', 'false', 'bool', NULL, NULL,  'Rappel visuel MFA pour les administrateurs',    1),
  ('auth.self_registration',          'false', 'bool', NULL, NULL,  'Création de compte par les visiteurs',          1),
  ('files.max_upload_mb',             '10',    'int',  1,   512,   'Taille maximale d''un téléversement (MB)',        1),
  ('urls.allow_private_hosts',        'false', 'bool', NULL, NULL,  'Autoriser l''analyse d''hôtes internes (SSRF)', 0),
  ('agents.parallel_workers',         '3',     'int',  1,   16,    'Sous-tâches d''agents exécutées en parallèle',   1),
  ('maintenance.mode',                'false', 'bool', NULL, NULL,  'Mode maintenance (écritures réservées aux admins)', 0);
