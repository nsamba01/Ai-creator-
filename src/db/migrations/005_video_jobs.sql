-- Phase B de l'agent Vidéo : file d'exécution + artefacts rattachés + lecture en continu.
--
-- Pourquoi une table propre plutôt que `agent_tasks` : la file d'exécution d'un média a
-- besoin d'un verrou de bail (qui le traite, jusqu'à quand), d'un compteur de tentatives
-- et d'un réveil différé. `agent_tasks` n'a aucune de ces colonnes, et les lui ajouter
-- aurait modifié une table appliquée depuis la migration 001 — interdiction absolue.
-- `video_jobs` est donc la file d'exécution ; `agent_tasks` reste la file *métier*
-- (ce que l'opérateur voit dans « Tâches »), les deux étant reliées par `job_id`.

-- Rattachement des artefacts (vignette, piste audio extraite, rapport) à leur source :
-- ils héritent ainsi du propriétaire, du quota et de la suppression en cascade, sans
-- inventer un second contrôle d'accès.
ALTER TABLE files ADD COLUMN parent_file_id INTEGER REFERENCES files(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_files_parent ON files (parent_file_id);

CREATE TABLE IF NOT EXISTS video_jobs (
  id            INTEGER PRIMARY KEY,
  video_id      INTEGER NOT NULL REFERENCES video_assets(id) ON DELETE CASCADE,
  file_id       INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  owner_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind          TEXT NOT NULL CHECK (kind IN ('probe','transcode','transcribe','thumbnail','moderation')),
  status        TEXT NOT NULL DEFAULT 'queued'
                  CHECK (status IN ('queued','running','succeeded','failed','cancelled')),
  attempts      INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0 AND attempts <= 64),
  max_attempts  INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts >= 1 AND max_attempts <= 16),
  priority      INTEGER NOT NULL DEFAULT 5 CHECK (priority BETWEEN 0 AND 9),
  -- Verrou de bail : un worker ne « possède » une tâche que le temps du lease. S'il meurt,
  -- la tâche redevient claimable au lieu de bloquer la file indéfiniment.
  locked_by     TEXT,
  locked_at     TEXT,
  lease_expires_at TEXT,
  run_after     TEXT,
  error_code    TEXT,
  error_message TEXT CHECK (error_message IS NULL OR length(error_message) <= 500),
  progress      INTEGER CHECK (progress IS NULL OR (progress >= 0 AND progress <= 100)),
  input_json    TEXT CHECK (input_json IS NULL OR length(input_json) <= 8000),
  result_json   TEXT CHECK (result_json IS NULL OR length(result_json) <= 30000),
  job_task_id   INTEGER REFERENCES agent_tasks(id) ON DELETE SET NULL,
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  started_at    TEXT,
  finished_at   TEXT,
  -- Idempotence : rejouer une analyse ne crée pas de doublon, cela remet la ligne en file.
  UNIQUE (video_id, kind)
);

-- Claim : (status, run_after, id). Ramassage de bails expirés : (lease_expires_at).
CREATE INDEX IF NOT EXISTS idx_video_jobs_claim ON video_jobs (status, run_after, id);
CREATE INDEX IF NOT EXISTS idx_video_jobs_lease ON video_jobs (status, lease_expires_at);
CREATE INDEX IF NOT EXISTS idx_video_jobs_owner ON video_jobs (owner_id, id);

CREATE TRIGGER IF NOT EXISTS touch_video_jobs_updated_at
BEFORE UPDATE ON video_jobs
FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at
BEGIN
  UPDATE video_jobs SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id;
END;

-- Deux permissions de plus (total 33) : recevoir des octets et piloter la file ne sont
-- pas des droits de lecture de rapport.
INSERT OR IGNORE INTO permissions (key, category, description, is_dangerous) VALUES
  ('videos:stream',     'agents', 'Recevoir les octets d''une vidéo prête',              0),
  ('videos:manage-jobs','agents', 'Annuler, relancer ou purger la file d''exécution',    1);

INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'ADMIN' AND p.key IN ('videos:stream','videos:manage-jobs');

-- Un compte standard peut lire SES vidéos déjà déclarées prêtes ; la portée est filtrée
-- dans le service, jamais dans l'interface.
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.key = 'videos:stream'
WHERE r.name = 'USER';

-- Réglages : tout est éteint par défaut au livraison, y compris la lecture en continu,
-- qui est la première route du produit à renvoyer des octets de média.
INSERT OR IGNORE INTO settings (key, value_json, value_type, min_value, max_value, description, is_public) VALUES
  ('video.stream_enabled',  'false', 'bool', NULL, NULL,   'Autoriser la lecture en continu (Range) des vidéos prêtes', 1),
  ('video.async_probe',     'false', 'bool', NULL, NULL,   'Sonder via la file d''exécution au lieu de le faire dans la requête', 0),
  ('video.lease_seconds',   '120',   'int',  5,    3600,  'Durée du bail d''un worker avant reprise de la tâche',       0),
  ('video.max_attempts',    '3',     'int',  1,    10,    'Tentatives maximum avant échec définitif d''un job',        0),
  ('video.backoff_seconds', '2',      'int', 0,    3600,  'Attente initiale avant nouvelle tentative (doublement à chaque échec)', 0),
  ('video.worker_concurrency','1',    'int', 1,    8,     'Jobs traités en parallèle par un même processus worker',                0);
