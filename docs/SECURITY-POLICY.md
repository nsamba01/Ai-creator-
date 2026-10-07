# Politique de sécurité et traitement des secrets

Portée : tout contribution, tout déploiement, tout journal de ce projet. Cette politique est
opposable aux outils (`npm run check` la fait respecter mécaniquement), pas seulement aux
intentions.

## 1. Règles non négociables

1. **Aucun secret dans le dépôt.** Clefs API, mots de passe, jetons, certificats privés,
   `SESSION_SECRET`/`STATE_SECRET`, URLs de connexion avec identifiants. `.gitignore` exclut
   `.env*` (sauf `.env.example`), `data/`, `*.db`, `*.pem`, `*.key` ; `npm run audit` vérifie
   aussi l'**index Git**, car un fichier ignoré mais déjà suivi ne l'est pas vraiment.
2. **Aucun secret dans un journal.** Le `redact()` du `src/utils/logger.js` masque par nom de
   clé (`password`, `token`, `secret`, `cookie`, `csrf`, `*_hash`, `salt`, `authorization`,
   `bearer`) dans les objets imbriqués et les tableaux. La règle d'écriture reste
   « on ne journalise pas une valeur sensible » : une clef noyée dans une phrase libre n'est
   pas rattrapée, et c'est volontaire (un journal « nettoyé » par substitution aveugle
   devient inutilisable pour l'enquête).
3. **Aucun secret dans une réponse API, un HTML ou un bundle JS.** Le frontend ne reçoit que
   `meta` publique, des empreintes et des compteurs. Les hachés d'`argon2` ne sortent jamais
   de la base (`/healthz` a été corrigé sur ce point précis pendant le chantier).
4. **Aucun mot de passe en argument de ligne de commande** (visible dans `ps` et dans
   l'historique du shell) : `BOOTSTRAP_ADMIN_PASSWORD` dans l'environnement d'un processus
   déjà protégé, `--password-file`, ou génération dans un fichier `0600`.
5. **Aucun mot de passe dans les fichiers de test.** Les fixtures utilisent des valeurs
   évidentes et hors du dictionnaire des mots de passe réels (`tests/helpers.js`), et
   `npm run audit` refuserait une valeur qui ressemble à un secret de production.
6. **Rotation en cas de doute, puis retrait de la source.** Un secret ayant transité par un
   journal, une capture, un message ou un commit est considéré compromis : on le révoque
   d'abord, on le remplace ensuite, on nettoie le dépôt ensuite seulement.

## 2. Ce que font les outils

| Outil | Comportement |
|---|---|
| `node scripts/security-audit.js` | scan de 100 fichiers du contexte de travail (9 motifs de secret), index Git (`git ls-files` + recherche de clés privées), permissions des fichiers de secrets locaux, exécution réelle des gardes de configuration, contrôle `Dockerfile`/`docker-compose.yml`, `npm audit --omit=dev`. Un secret trouvé est **signalé par son chemin et son numéro de ligne**, jamais par sa valeur. Règle de sévérité : une correspondance dans un fichier **ignoré et non suivi** (le `.env` local, `data/`) est comptée et affichée en réserve, pas en constat — mais `git add -f .env` fait immédiatement repasser le constat en `CRITICAL` (vérifié). `--strict` rend une sortie non nulle, `--json` est consommable par la CI. |
| `node scripts/lint.js` | motifs de secrets dans les sources, primitives dangereuses, `console.*` dans `src/`, interpolation SQL, cohérence `.env.example` ↔ code. Une dérogation s'écrit `// lint-allow: <motif>` (trois dans l'auditeur, pour ses appels `git`/`npm` en lecture seule) et le lint **compte** les dérogations dans son résumé. |
| `npm test` | vérifie le **comportement** : masquage au sink, en-têtes, CSRF, refus des secrets faibles au démarrage, échappement de rendu |
| `docker/entrypoint.sh` | secrets générés en `0600` dans le volume, jamais en variable permanente du conteneur, jamais écrasés si déjà présents |

## 3. Procédure : un secret a fuité

1. Révoquer la valeur (rotation côté fournisseur, ou nouvelle paire de secrets applicatifs).
2. Retirer la valeur du fichier fautif ; si elle est entrée dans l'historique Git, purger
   l'historique **ou** assumer la rotation comme seule mitigation (le fork d'un dépôt ne se
   rattrape pas) — décision humaine, jamais automatique.
3. Mettre à jour le déploiement avec la nouvelle valeur (`docker compose up -d`, `systemctl
   restart`), vérifier que les anciennes sessions sont invalidées si `SESSION_SECRET` change :
   c'est le comportement attendu, pas une régression.
4. Consigner l'événement dans l'audit de l'application (l'événement est écrit par le serveur,
   un incident hors ligne se note dans `docs/` ou le système de tickets).
5. Ajouter un cas de test ou un motif d'audit pour que la même fuite ne se reproduise pas.

## 4. Procédure : changement d'un mot de passe administrateur

```bash
docker compose exec app node scripts/bootstrap-admin.js --rotate
# le nouveau mot de passe temporaire est écrit en 0600 dans le volume :
docker compose exec app sh -c 'cat /app/data/bootstrap-admin-password && rm /app/data/bootstrap-admin-password'
```

Toutes les sessions du compte sont révoquées, `must_change_password` est remis à 1, et
l'événement `admin.password.rotated` est journalisé en sévérité `critical`.

## 5. Ce qui est refusé au démarrage (et non « averti »)

En `NODE_ENV=production` : CSRF désactivé, cookie `SameSite=none` sans `Secure`, CORS `*`
avec cookies, `DISABLE_AUTH_FOR_TESTS=1`, `SESSION_SECRET`/`STATE_SECRET` absents, courts
(< 32 caractères) ou placeholder connus. La génération automatique n'intervient qu'avec
l'opt-in explicite `SECRET_ALLOW_GENERATED=1`. Sortie du processus : `78` (`EX_CONFIG`).

## 6. Hygiène de développement

* Branche dédiée par chantier, `git status` et `git diff` relus avant tout grand changement.
* Aucune opération destructive (`reset --hard`, `clean -fdx`, purge d'historique, suppression
  de volume) sans validation humaine explicite.
* `data/` n'est jamais ajouté : la base, les fichiers téléversés et les secrets générés y vivent.
* Les captures d'écran de l'interface d'administration avant publication sont relues :
  les Empreintes IP/UA et les IDs de session ne sont pas des secrets, les jetons de
  réinitialisation affichés dans un devtools, si.

## 7. Signalement

Les vulnérabilités se signalent au responsable du dépôt (issue privée ou canal prévu par
l'organisation), avec reproduction minimale, impact et correctif proposé. Délai de
divulgation recommandé : 90 jours ou correctif disponible. Ce dépôt ne fournit pas de
programme de bug bounty : il n'y a pas d'adresse de contact certifiée ici, et l'inventer
serait une faute.
