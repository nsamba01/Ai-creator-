-- Garantie d’horodatage.
--
-- Le schéma pose un DEFAULT sur updated_at, mais un DEFAULT ne s’applique
-- qu’à l’INSERT : sans trigger, un UPDATE qui oublie la colonne laisse une
-- ligne « jamais modifiée ». Les triggers ci-dessous rattrapent cet oubli,
-- et seulement lui : quand l’appelant a déjà posé sa valeur
-- (NEW.updated_at IS NOT OLD.updated_at), le déclencheur ne rejoue pas.
--
-- La récursion est impossible ici : PRAGMA recursive_triggers est laissé à sa
-- valeur par défaut (OFF), donc l’UPDATE interne ne redéclenche pas le
-- trigger. SQLite est la seule source de vérité de l’application.

CREATE TRIGGER IF NOT EXISTS touch_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at
BEGIN
  UPDATE users SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS touch_roles_updated_at
BEFORE UPDATE ON roles
FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at
BEGIN
  UPDATE roles SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS touch_settings_updated_at
BEFORE UPDATE ON settings
FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at
BEGIN
  UPDATE settings SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE key = NEW.key;
END;

CREATE TRIGGER IF NOT EXISTS touch_agent_tasks_updated_at
BEFORE UPDATE ON agent_tasks
FOR EACH ROW
WHEN NEW.updated_at IS OLD.updated_at
BEGIN
  UPDATE agent_tasks SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id;
END;
