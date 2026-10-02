# Tests et chaîne de qualité

## Commandes

```bash
npm test                      # 197 tests, 25 suites, une seule file (--test-concurrency=1)
npm run test:one -- tests/rbac.test.js   # un seul fichier de suite
npm run lint                  # portique statique maison (aucune dépendance externe)
npm run audit                 # audit de sécurité (secrets, index Git, config, Docker, npm audit)
npm run build                 # build Vite de l'interface (nécessaire pour que / serve la SPA)
npm run check                 # lint + tests + audit : c'est LE contrôle à passer avant de committer
npm run smoke                 # 27 contrôles contre une instance réellement en cours d'exécution
```

`npm run check` est ce que la CI exécute (`.github/workflows/ci.yml`). Résultat mesuré le 2026-10-02 dans cet
environnement : lint `Aucun problème détecté` (sortie 0), **197 tests, 0 échec**,
audit sans constat ouvert hors environnement connecté, smoke **27/27** sur une instance
de production locale.

## Ce que couvre chaque suite

| Fichier | Contenu (résumé) |
|---|---|
| `tests/db.test.js` | migrations (ordre, idempotence, empreinte SHA-256 et **détection de falsification**), pragmas, contraintes `CHECK`/`UNIQUE`, transactions, `foreign_keys`, `updated_at` entretenu par le déclencheur de `003`, colonnes réelles |
| `tests/password.test.js` | aller-retour PHC, sel unique, vérification à temps constant, `needsRehash`, politique de complexité, dictionnaire et variantes « leet », refus du nom d'utilisateur, génération de mots de passe provisoires sans caractère ambigu |
| `tests/auth.test.js` | connexion, 401 générique identique pour mot de passe faux/inconnu/compte désactivé, changement forcé, rotation de session, expiration, révocation, refresh : rotation, détection de réemploi et révocation de la famille, réinitialisation à usage unique, journalisation des événements d'authentification |
| `tests/rbac.test.js` | 27 permissions seeds, matrice ADMIN/USER, refus par défaut route par route, anti-escalade (donner une permission qu'on ne détient pas), dernier administrateur protégé, cache invalidé, portée des données d'un `USER` |
| `tests/admin.test.js` | tableau de bord agrégé, édition de configuration typée et bornée, file de tâches d'agents, révocation de toutes les sessions, posture de sécurité exposée |
| `tests/audit.test.js` | immuabilité (`UPDATE`/`DELETE` refusés par déclencheurs), champs présents, IP/UA sous forme d'empreinte, pagination/filtres, aucune valeur sensible écrite |
| `tests/files.test.js` | téléversement (extension + MIME + signature binaire), refus des vecteurs d'exécution, taille et quota, nommage UUID et résistance à `../`, dé-duplication par propriétaire, re-téléchargement, suppression logique + unlink, IDOR (lire/effacer le fichier d'autrui), compteur de téléchargements |
| `tests/documents.test.js` | DOCX/XLSX (limites ZIP : taille décompressée, ratio, nombre d'entrées), CSV/TSV, JSON, Markdown, PDF heuristique, images (dimensions), masquage des sécrètes détectées |
| `tests/url.test.js` | classification SSRF (IPv4/IPv6, plages réservées, `::ffff:127.0.0.1`, `2002::`), ports, redirections, délai, plafond d'octets, ré-épreuve de l'adresse résolue, aucune trace d'identifiants dans l'URL journalisée |
| `tests/security.test.js` | en-têtes et CSP, cookies (HttpOnly/`secure`/`SameSite`), CSRF double-submit + jeton de session, 401/403/404 normalisés sans fuite, échappement de rendu (charge XSS stockée puis rendue inerte), `redact()` au sink, charge utile JSON limite, refus des clés inconnues, **lecteur `.env`** (priorité à l'environnement, symlink/hors-racine refusés, aucune valeur journalisée) |

## Harnais (`tests/helpers.js`)

`boot({ adminPassword, userPassword, extra })` lève une instance **réelle** de
l'application pour chaque test : répertoire `DATA_DIR` temporaire, port `0` (le serveur
choisit), `NODE_ENV=test`, `COOKIE_SECURE=0`, `SameSite=lax`, paramètres Argon2 abaissés
pour la vitesse (le format et les chemins de code restent ceux de la production), limite de
corps relevée pour les tests de fichiers. Il renvoie un client `fetch` avec **pot de
cookies** et **jeton CSRF** gérés automatiquement, des builders de documents (zip, docx,
xlsx, pdf, PNG) fabriqués à la volée dans le test, et `close()` qui referme base et
serveur.

Règles d'écriture, issues des faux positifs rencontrés :

1. **jamais de réseau** dans un test : toute URL sortante est simulée ou attendue refusée ;
2. ne pas dépendre d'une temporisation (les tests de verrouillage comptent des requêtes,
   pas des secondes) ;
3. comparer une charge XSS sur `JSON.stringify(...)`, jamais sur l'objet (l'échappement est
   une propriété du rendu) ;
4. `assert.ok(cond, msg)` et non `assert.equal(cond, true, msg)` (le second avale le
   message) ;
5. les assertions textuelles doivent contenir les **mots français réellement produits** par
   le serveur ;
6. une fixture ne doit jamais contenir le nom d'utilisateur dans son mot de passe
   (politique serveur), ni un secret qui serait réduit par `redact()` si elle est
   journalisée ;
7. un compte en `must_change_password` est bloqué hors liste blanche : les fixtures
   d'API le changent d'abord.

## Portique de lint (`scripts/lint.js`)

`node --check` sur les 61 fichiers JS (les `.jsx` sont exclus : le parseur Node ne connaît
pas le JSX), vérification que chaque import relatif résout, motifs de secrets dans les
sources, primitives dangereuses (`child_process`, `eval`, `Function`), `console.*` interdit
dans `src/`, interpolation SQL, garde anti-`DROP` dans les migrations, présence obligatoire
de `.gitignore` et `.dockerignore`, **cohérence bidirectionnelle** `.env.example` ↔
`process.env.*` lus par le code. `tests/` et `docs/` (+ `README.md`) sont traités comme des fixtures : la documentation
**nomme** les primitives dangereuses et les tests manipulent des identifiants fictifs ;
on n'y recherche donc que les fuites à haute confiance (clés AWS, clés privées, jetons
SaaS). Le code applicatif et les scripts restent stricts, avec une dérogation possible
par commentaire `// lint-allow: <motif>` sur les trois lignes qui précèdent — chaque
dérogation est **comptée et affichée** dans le résumé du lint (trois aujourd'hui, toutes
dans `scripts/security-audit.js` pour `git ls-files` et `npm audit` en lecture seule).
Sortie non nulle = CI rouge.

## Migrations

`src/db/migrations/*.sql` sont appliquées dans l'ordre numérique au démarrage et par
`npm run db:migrate`. Chaque fichier est horodaté par empreinte SHA-256 dans
`schema_migrations` : modifier une migration déjà appliquée fait échouer le démarrage.
**Toute correction passe donc par un nouveau fichier numéroté** (exemple en place :
`003_touch_updated_at.sql` ajoute l'entretien de `updated_at`, sans retoucher `001`).
Un test d'échec de vérification d'empreinte protège cette règle.

## Ce qui n'est pas couvert

* Pas de test navigateur (Playwright) : la chaîne de rendu est vérifiée par des assertions
  structurelles côté serveur + absence de `dangerouslySetInnerHTML`.
* Pas de test de charge ni de test de reprise après sinistre.
* Pas de test d'intrusion : `smoke-test.js` vérifie la posture, pas l'exploitabilité.
