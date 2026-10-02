# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------------------
# PrinceNsamba AI — image de production
#
# Contraintes de ce projet, rappelées ici parce qu'elles structurent l'image :
#   * aucune dépendance native (pas de node-gyp, pas d'argon2 compilé) :
#     Argon2id vient de @noble/hashes (pur JS) et SQLite de `node:sqlite` ;
#   * donc l'image « runtime » n'a besoin d'aucun toolchain, d'aucun paquet
#     système, et d'aucune phase de compilation côté éditeur ;
#   * le frontend est construit à part (Vite) puis servi par l'API : le stage
#     `web` produit uniquement `dist/`.
#
# Épinglage : `node:22-bookworm-slim` suit la ligne 22.x. En déploiement réel,
# remplacez par l'empreinte exacte pour une build reproductible :
#   docker buildx imagetools inspect node:22-bookworm-slim  # -> Digest: sha256:...
#   FROM node:22-bookworm-slim@sha256:<digest>
# ---------------------------------------------------------------------------

# --------------------------- stage 1 : build du frontend -------------------
FROM node:22-bookworm-slim AS web
ENV NODE_ENV=development
WORKDIR /app
# Le cache npm est monté, jamais copié dans l'image.
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY index.html vite.config.js ./
COPY client ./client
RUN npm run build && du -sh dist && ls -l dist

# --------------------------- stage 2 : dépendances de prod ------------------
FROM node:22-bookworm-slim AS prod-deps
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force

# --------------------------- stage 3 : production ---------------------------
FROM node:22-bookworm-slim AS production

ENV NODE_ENV=production \
    PORT=3000 \
    HOST=0.0.0.0 \
    DATA_DIR=/app/data \
    NODE_OPTIONS=--disable-warning=ExperimentalWarning

WORKDIR /app

# Utilisateur dédié, sans shell ni home : le conteneur ne tourne jamais en root.
RUN groupadd --gid 10001 prince \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin prince

COPY --from=prod-deps --chown=prince:prince /app/node_modules ./node_modules
COPY --from=web --chown=prince:prince /app/dist ./dist
COPY --chown=prince:prince package.json ./
COPY --chown=prince:prince src ./src
COPY --chown=prince:prince scripts ./scripts
COPY --chown=prince:prince docker/entrypoint.sh /usr/local/bin/entrypoint.sh

# Le volume de données : créé ici pour que l'image démarrer seule (sans mount),
# mais il DOIT être monté en production (sessions, base, fichiers téléversés).
RUN chmod 0755 /usr/local/bin/entrypoint.sh \
 && mkdir -p /app/data/uploads \
 && chown -R prince:prince /app/data /app/src /app/scripts

USER 10001:10001
EXPOSE 3000

# Sonde de vie : `node` suffit, aucun paquet système additionnel nécessaire.
HEALTHCHECK --interval=20s --timeout=5s --start-period=20s --retries=5 \
  CMD node -e "const p=process.env.PORT||3000;fetch('http://127.0.0.1:'+p+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["node", "src/server.js"]

# --------------------------- stage 4 : tests --------------------------------
# `docker compose --profile test run --rm test` rejoue lint + suite + audit.
FROM node:22-bookworm-slim AS test
ENV NODE_ENV=test \
    DATA_DIR=/tmp/ps-data \
    NODE_OPTIONS=--disable-warning=ExperimentalWarning
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
# Le lint vérifie la présence des fichiers d’exclusion ; ils ne sont pas copiés
# par `COPY . .` (`.dockerignore` sert au builder, il n’entre pas dans l’image).
COPY .gitignore .dockerignore ./
# La coquille construite permet aux tests de vérifier le service du frontend.
COPY --from=web /app/dist ./dist
RUN mkdir -p /tmp/ps-data && chmod -R a+rX /app
# Le conteneur de tests n’a aucune raison de tourner en root.
USER node
CMD ["sh", "-c", "node scripts/lint.js && node --test --test-concurrency=1 \"tests/*.test.js\" && node scripts/security-audit.js"]
