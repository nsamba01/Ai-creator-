-- 006_video_tools.sql — traitement hors-bande : vignettes et pistes audio (phase C)
--
-- Aucun nouvel objet à créer : la table `video_jobs` (005) porte déjà le bail, le compteur de
-- tentatives et le rattachement d'artefacts (`files.parent_file_id`). Cette migration n'ajoute que
-- les réglages, parce qu'exécuter un décodeur externe est une capacité que l'administrateur ouvre
-- explicitement — et non une variable d'environnement de plus, qui forcerait un redéploiement pour
-- la refermer.
PRAGMA foreign_keys = ON;

INSERT OR IGNORE INTO settings (key, value_json, value_type, min_value, max_value, description, is_public) VALUES
  ('video.tools_enabled',     'false', 'bool', NULL, NULL,      'Autoriser le worker à exécuter un outil média (ffmpeg) pour vignettes et pistes audio', 0),
  ('video.thumbnail_width',   '320',   'int',  32,    1920,     'Largeur maximale de la vignette produite, en pixels',                                 0),
  ('video.thumbnail_at_ms',   '1000',  'int',  0,     86400000, 'Position de lecture à laquelle on tire la vignette, en millisecondes',               0),
  ('video.thumbnail_max_kb',  '512',   'int',  8,     65536,    'Taille maximale acceptée pour une vignette, en kibioctets : au-delà la sortie est jetée', 0),
  ('video.audio_max_seconds', '300',   'int',  1,     3600,     'Durée maximale extraite pour une piste audio, en secondes',                          0);
