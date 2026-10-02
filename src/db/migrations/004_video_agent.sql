-- Phase A de l'agent Vidéo : ingestion + sondage d'en-tête.
--
-- Périmètre volontaire : AUCUN transcodage, AUCUN binaire obligatoire.
-- Seules les métadonnées de conteneur sont stockées, jamais l'image média.
-- Le moteur de traitement (worker séparé, ffmpeg/ffprobe bornés) est décrit
-- dans docs/VIDEO-AGENT.md et arrivera en phase B ; cette migration pose le
-- modèle de données et les permissions correspondantes.

CREATE TABLE IF NOT EXISTS video_assets (
  id            INTEGER PRIMARY KEY,
  file_id       INTEGER NOT NULL UNIQUE REFERENCES files(id) ON DELETE CASCADE,
  owner_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  container     TEXT,
  brand         TEXT,
  codec         TEXT,
  duration_ms   INTEGER CHECK (duration_ms IS NULL OR (duration_ms >= 0 AND duration_ms <= 86400000)),
  width         INTEGER CHECK (width IS NULL OR (width >= 0 AND width <= 16384)),
  height        INTEGER CHECK (height IS NULL OR (height >= 0 AND height <= 16384)),
  fps           REAL    CHECK (fps IS NULL OR (fps > 0 AND fps <= 1000)),
  bitrate_bps   INTEGER CHECK (bitrate_bps IS NULL OR (bitrate_bps >= 0 AND bitrate_bps <= 10000000000)),
  track_count   INTEGER CHECK (track_count IS NULL OR (track_count >= 0 AND track_count <= 1000)),
  parser        TEXT,
  probe_source  TEXT NOT NULL DEFAULT 'none' CHECK (probe_source IN ('none','header','ffprobe','header+ffprobe')),
  status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','probing','ready','failed','quarantined')),
  error_code    TEXT,
  notes         TEXT CHECK (notes IS NULL OR length(notes) <= 1000),
  meta_json     TEXT CHECK (meta_json IS NULL OR length(meta_json) <= 16000),
  file_size_bytes INTEGER NOT NULL DEFAULT 0 CHECK (file_size_bytes >= 0),
  sha256        TEXT,
  task_id       INTEGER REFERENCES agent_tasks(id) ON DELETE SET NULL,
  probed_at     TEXT,
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  deleted_at    TEXT
);

CREATE INDEX IF NOT EXISTS idx_video_assets_owner  ON video_assets (owner_id, deleted_at);
CREATE INDEX IF NOT EXISTS idx_video_assets_status ON video_assets (status, id);
CREATE INDEX IF NOT EXISTS idx_video_assets_file   ON video_assets (file_id);

CREATE TABLE IF NOT EXISTS video_analyses (
  id          INTEGER PRIMARY KEY,
  video_id    INTEGER NOT NULL REFERENCES video_assets(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL CHECK (kind IN ('probe','transcode','transcribe','thumbnail','moderation')),
  status      TEXT NOT NULL DEFAULT 'ok' CHECK (status IN ('ok','partial','failed')),
  model       TEXT,
  result_json TEXT CHECK (result_json IS NULL OR length(result_json) <= 30000),
  error       TEXT,
  cost_ms     INTEGER CHECK (cost_ms IS NULL OR (cost_ms >= 0 AND cost_ms <= 86400000)),
  created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE (video_id, kind)
);

CREATE INDEX IF NOT EXISTS idx_video_analyses_video ON video_analyses (video_id, kind);

-- Ramassage de file : le futur worker interroge (agent_role, status, id).
-- `agent_tasks` connaît déjà le rôle « video » (001) : aucun ajout de colonne
-- n'est nécessaire en phase A, la tâche sert de traçabilité d'exécution.
CREATE INDEX IF NOT EXISTS idx_agent_tasks_role_status ON agent_tasks (agent_role, status, id);

-- Horodatage entretenu, comme pour les autres tables (cf. 003).
CREATE TRIGGER IF NOT EXISTS touch_video_assets_updated_at
BEFORE UPDATE ON video_assets
FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at
BEGIN
  UPDATE video_assets SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id;
END;

-- Quatre permissions de plus : le total passe de 27 à 31.
INSERT OR IGNORE INTO permissions (key, category, description, is_dangerous) VALUES
  ('videos:upload',    'agents', 'Déclarer et sonder une vidéo',                     0),
  ('videos:read',      'agents', 'Consulter le rapport de ses propres vidéos',       0),
  ('videos:read:any',  'agents', 'Consulter les vidéos d''un autre utilisateur',     1),
  ('videos:process',   'agents', 'Relancer un sondage, lever une mise en quarantaine', 1);

-- ADMIN : toutes les permissions (la règle d'attribution globale est dans 002,
-- elle ne s'applique pas aux lignes insérées ensuite : on les ajoute ici).
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'ADMIN'
  AND p.key IN ('videos:upload','videos:read','videos:read:any','videos:process');

-- USER : dépôt et consultation de SES vidéos. Jamais celles d'autrui, jamais la
-- levée de quarantaine.
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r
JOIN permissions p ON p.key IN ('videos:upload','videos:read')
WHERE r.name = 'USER';

-- Réglages pilotés par l'interface (schéma déjà validé par settings.service).
INSERT OR IGNORE INTO settings (key, value_json, value_type, min_value, max_value, description, is_public) VALUES
  ('video.enabled',              'false', 'bool', NULL, NULL,  'Activer l''ingestion et le sondage vidéo',                    1),
  ('video.max_duration_seconds', '3600',  'int',  1,    86400, 'Durée maximale acceptée avant mise en quarantaine',           1),
  ('video.use_ffprobe',          'true',  'bool', NULL, NULL,  'Sonder avec ffprobe quand le binaire est disponible',         0);
