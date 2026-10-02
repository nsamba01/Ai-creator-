#!/bin/sh
# ---------------------------------------------------------------------------
# PrinceNsamba AI — point d’entrée du conteneur
#
# Que fait ce script, et pourquoi :
#   1. il vérifie que le volume de données est inscriptible AVANT de démarrer :
#      sans cela l’application échouerait à la première écriture (session,
#      téléversement) après avoir accepté des connexions ;
#   2. il fournit des secrets persistés si l’opérateur n’a rien fourni : la
#      génération est écrite dans le volume en 0600, jamais affichée. Sans
#      cela, en production, le démarrage est refusé par la garde de
#      configuration (choix délibéré : un secret régénéré à chaque redémarrage
#      invaliderait toutes les sessions en silence) ;
#   3. il applique les migrations (idempotentes, empreinte SHA-256 vérifiée) ;
#   4. il exec le processus Node comme PID 1 pour que SIGTERM/SIGINT arrivent
#      correctement à l’arrêt gracieux (fin des requêtes en cours).
#
# Aucun secret n’est jamais écrit sur la sortie standard, ni ici ni ailleurs.
# ---------------------------------------------------------------------------
set -eu

umask 077

: "${DATA_DIR:=/app/data}"
export DATA_DIR
: "${PORT:=3000}"
: "${HOST:=0.0.0.0}"

log() {
  printf '[entrypoint] %s\n' "$1"
}

# --- 1. volume de données ---------------------------------------------------
if ! mkdir -p "$DATA_DIR/uploads" 2>/dev/null; then
  log "ERREUR : $DATA_DIR n’est pas inscriptible."
  log "montez un volume (docker-compose.yml le fait) dont le propriétaire est l’uid 10001, par ex. :"
  log "  docker run --rm -v princesamba_data:/app/data --user 0:0 alpine chown -R 10001:10001 /app/data"
  exit 78 # EX_CONFIG : problème de configuration, pas de l’application
fi

if ! [ -w "$DATA_DIR" ]; then
  log "ERREUR : $DATA_DIR existe mais n’est pas accessible en écriture par uid=$(id -u)."
  log "corrigez le propriétaire du volume (voir la commande ci-dessus) puis relancez."
  exit 78
fi

# --- 2. secrets --------------------------------------------------------------
# La logique est écrite en Node : même runtime, mêmes règles que l’application,
# et pas de dépendance à openssl(1) dans l’image.
node -e '
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const dir = process.env.DATA_DIR;
for (const name of ["SESSION_SECRET", "STATE_SECRET"]) {
  if ((process.env[name] ?? "").trim().length >= 32) continue;
  const file = path.join(dir, ".secret-" + name.toLowerCase());
  if (fs.existsSync(file) && fs.readFileSync(file, "utf8").trim().length >= 32) {
    console.log("[entrypoint] " + name + " : lu depuis le volume (0600)");
    continue;
  }
  const value = crypto.randomBytes(32).toString("hex");
  const fd = fs.openSync(file, "wx", 0o600);
  try { fs.writeSync(fd, value + "\n"); } finally { fs.closeSync(fd); }
  try { fs.chmodSync(file, 0o600); } catch {}
  console.log("[entrypoint] " + name + " généré dans " + file + " — à fournir explicitement au prochain déploiement, puis à révoquer si la machine est partagée.");
}
'

# --- 3. migrations ------------------------------------------------------------
# Idempotent : la table schema_migrations porte l’empreinte de chaque fichier ;
# une migration déjà appliquée et modifiée est refusée (le conteneur ne démarre
# pas sur un schéma ambigu).
if node src/db/migrate.js; then
  log "migrations à jour"
else
  log "ERREUR : les migrations ont échoué (schéma modifié après application, volume d’un autre environnement ?)"
  exit 78
fi

# --- 4. application ------------------------------------------------------------
log "démarrage : node $* (port $PORT, hôte $HOST, données $DATA_DIR)"
exec "$@"
