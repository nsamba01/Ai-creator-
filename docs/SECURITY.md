# Sécurité

Ce document décrit la menace et la réponse apportée, avec le pointeur de code
qui permet de vérifier chaque affirmation. Il ne prétend pas à l'exhaustivité :
la fin liste les limites connues.

## 1. Identité et mots de passe

| Exigence | Mise en œuvre | Vérifiable dans |
|---|---|---|
| Hachage fort, jamais de clair | Argon2id (version 19, `m=19456,t=3,p=2`, empreinte 32 o) au format PHC `$argon2id$v=19$m,t,p$sel$empreinte` | `src/services/password.service.js` |
| Sel unique | 16 octets `crypto.randomBytes` par mot de passe, stocké dans la chaîne PHC | idem |
| Comparaison à temps constant | `crypto.timingSafeEqual` sur les empreintes décodées | `verifyPassword` |
| Ré-hachage progressif | les paramètres utilisés sont stockés (`hash_params`) ; une connexion avec des paramètres plus faibles renvoie `needsRehash` et la ligne est réécrite | `verifyPassword`, `auth.service.js` |
| Complexité | longueur minimale configurable (12 en production), 3 classes de caractères, pas 4 répétitions consécutives, pas de caractère de contrôle, pas de nom/identifiant de l'utilisateur dans le mot de passe | `assertPasswordPolicy` |
| Dictionnaire, même déguisé | repli canonique : accents, casse, ponctuation, digits de fin et substitutions « leet » neutralisés avant comparaison à la liste des mots connus (`Password1`, `P@ssw0rd-2026`, `mot_de_passe123` sont refusés) | `foldCommon`, `isCommon` |
| Mot de passe provisoire non récupérable | généré par l'administrateur au créateur de compte, retourné **une seule fois** dans la réponse de création, jamais stocké en clair ; l'utilisateur le change à la première connexion | `users.routes.js`, `auth.service.js` |
| Changement forcé | `must_change_password = 1` ⇒ toute route hors liste blanche répond 403 `PASSWORD_CHANGE_REQUIRED` | `passwordChangeGate` (`src/app.js`) |
| Bourrage de connexion | triple limite : bucket mémoire par `(ipHash, identifiant)`, fenêtre persistante `login_attempts`, verrouillage de compte `locked_until` (5 tentatives / 15 min de fenêtre / 30 min de verrouillage par défaut) | `rate-limit.service.js`, `auth.service.js` |
| Réinitialisation sécurisée | jeton à usage unique, stocké sous forme `HMAC(secret, jeton)`, expiré/consommé, aucun jeton dans les journaux ni dans les URLs de réponse | `auth.service.js`, `password_reset_tokens` |

**Aucun mot de passe, aucune clef, aucun jeton n'apparaît** dans : le HTML, le JS
client, les réponses d'API, les messages d'erreur, les journaux applicatifs, le
dépôt Git. Le contrôle est automatisé par `scripts/security-audit.js` (présence)
et par `tests/security.test.js` (comportement).

## 2. Sessions et transport

* Cookies : `ps_session` (HttpOnly, SameSite=`strict`, `Secure` automatique dès que
  TLS est détecté), `ps_refresh` (HttpOnly, chemin limité à `/api/auth`),
  `ps_csrf` **lisible par le JS** (double-submit). Le préfixe `__Host-` est activable
  (`COOKIE_PREFIX=__Host-`) lorsque le site est en HTTPS bout en bout.
* Rotation de l'identifiant de session à la connexion et à tout changement de rôle ou
  de mot de passe : une session volée avant l'événement devient invalide.
* Jetons de rafraîchissement : rotation à chaque usage, `family_id` ; la réutilisation
  d'un jeton déjà consommé révoque **toute la famille**, déconnecte l'utilisateur et
  produit un événement `auth.refresh.reuse_detected` en sévérité `critical`.
* Révocation : par session, par compte (`revoke-all`), automatique à l'expiration, au
  changement de mot de passe, à la désactivation du compte et à la suppression logique.
* CSRF : en-tête `x-csrf-token` requis sur les méthodes modificatives, comparé au jeton
  de la **ligne de session** (pas seulement au cookie) ; les échecs sont journalisés
  (`security.csrf.failure`).
* CORS : liste d'origines explicite ; `*` est refusé au démarrage en production avec des
  cookies ; les requêtes portent `credentials: 'include'` uniquement depuis les origines
  listées.

## 3. Autorisation (RBAC)

* Modèle : `users ← user_roles → roles ← role_permissions → permissions`.
* **Refus par défaut** : chaque route nomme la permission qu'elle exige
  (`requirePermission('users:create')`). Il n'existe aucun test `if (isAdmin) skip`.
* 27 permissions, `ADMIN` les porte toutes (ligne seedée, modifiable en base),
  `USER` n'en porte que 6 (`dashboard:read`, `files:create`, `files:read`,
  `documents:analyze`, `urls:analyze`, `agents:read`).
* Portée des données : un `USER` ne voit que ses propres fichiers, ses propres sessions,
  son propre tableau de bord ; la lecture du fichier d'autrui exige `files:read:any`, la
  suppression `files:delete:any`, la révocation d'une session tierce `sessions:revoke:any`.
* Anti-escalade : un rôle ne peut recevoir que des permissions détenues par l'acteur ;
  un utilisateur ne peut pas se créer de rôle ni s'attribuer `ADMIN` ; le **dernier
  administrateur** ne peut être désactivé, dé-rôlé ni supprimé (409).
* Cache d'autorisation 15 s, invalidé à toute écriture de rôle/permission/session TTL.

## 4. Fichiers et documents

* Liste blanche d'extensions **et** de types MIME, **et** vérification des signature
  binaires (`FILE_SCAN_ENFORCE_MAGIC=1`) : un exécutable renommé `.png` est refusé.
* Interdiction explicite des vecteurs d'exécution ou de lecture navigateur :
  `.html .htm .svg .xhtml .js .mjs .cjs .sh .py .php .exe .dll .jar .bat .ps1 .vbs .apk .htmlapp`
  et les fichiers sans extension.
* Taille maximale (`MAX_UPLOAD_MB`), quota cumulé par utilisateur (`MAX_QUOTA_MB`),
  corps analysé en mémoire, jamais écrit par le middleware d'upload.
* Stockement : `DATA_DIR/uploads/<2 premiers hex de sha256>/<uuid>.<ext>` — le nom
  fourni n'est jamais utilisé pour un chemin, donc `../` n'a aucun effet ; la résolution
  est re-vérifiée (`resolveStored`) et doit rester sous le répertoire d'upload.
* Service : uniquement via l'API authentifiée, `Content-Disposition: attachment`,
  `X-Content-Type-Options: nosniff`, `Content-Security-Policy: sandbox`, type d'objet
  réécrit si le navigateur pourrait l'exécuter. Aucune route statique sur le volume.
* Dé-duplication par empreinte SHA-256 **par propriétaire**, sans copier deux fois les
  octets ; suppression = suppression logique en base + unlink physique.
* Analyse de documents : lecteurs écrits à la main (`zip.js` pour DOCX/XLSX avec
  limites d'entrée, de taille décompressée et de ratio, `documents.service.js` pour
  CSV/TSV, JSON, Markdown, PDF FlateDecode heuristique, PNG/JPEG/GIF/WebP/BMP pour les
  dimensions). Aucun fichier utilisateur n'est ouvert par un binaire externe.
* Vidéos : mêmes listes blanches, puis sondage **borné à la tête et à la queue du fichier**
  (`src/services/video-probe.js`) — le média n'est jamais décodé ni écrit ailleurs. Un
  conteneur inconnu, une géométrie aberrante ou un index manquant mettent l'actif en
  `quarantined` avec un `error_code`, jamais en lecture. `ffprobe` est doublement gardé
  (`VIDEO_USE_FFPROBE` **et** le réglage `video.use_ffprobe`), son chemin validé par
  `safeBinaryPath()` (ni `..`, ni métacaractère, bit d'exécution obligatoire), appelé sans
  shell avec une table d'arguments figée, un délai et un plafond de sortie d'1 Mio : aucun nom
  fourni par le client n'atteint la ligne de commande.
* Les sécrètes et données personnelles détectés dans un document sont **comptés**, jamais
  restitués (`redactHits`) ; le texte brut n'est renvoyé que sur demande explicite
  (`includeText`) et tronqué.

## 5. Sorties réseau (SSRF)

* Protocoles : `http`/`https` uniquement ; identifiant/mot de passe dans l'URL refusés.
* Ports : liste blanche (par défaut 80, 443, 8080, 8443).
* Adresses : classification IPv4 et IPv6 complète — bouclage, `0.0.0.0/8`, privés RFC1918,
  CGNAT `100.64/10`, `169.254/16` (métadonnées cloud), `198.18/15` (benchmark), multicast
  et réservées, `::1`, `::`, ULA `fc00::/7`, link-local `fe80::/10`, multicast `ff00::/12`,
  **plus les formes encapsulées** `::ffff:a.b.c.d`, `::a.b.c.d` et `2002::/16` (6to4) —
  sans quoi `http://[::ffff:127.0.0.1]/` contournerait le filtre.
* Noms : `localhost`, `*.local`, `*.internal`, `*.home`, `*.docker.internal`,
  `metadata.google.internal`, `host.docker.internal` sont refusés ; la **résolution DNS est
  re-contrôlée** pour chaque adresse rendue (`createSafeLookup`), ce qui ferme la porte au
  rebind DNS (résultat valide au contrôle, adresse interne à la connexion).
* Exécution : délai global (`URL_FETCH_TIMEOUT_MS`, 5 s), redirections limitées à
  `URL_MAX_REDIRECTS` (2) et re-validées, body plafonné à `URL_MAX_BYTES` (2 Mo),
  aucun en-tête d'authentification forwarding vers un autre hôte.
* Journal : chaque tentative (bloquée ou non) écrit `url_analyses` + un événement
  d'audit ; l'hôte est conservé, la requête et les identifiants sont supprimés
  (`safeHref`).
* Ouverture volontaire : `URL_ALLOW_PRIVATE_HOSTS=1` autorise l'interne — le démarrage
  le signale dans le journal, car cela transforme l'application en proxy interne.

## 6. En-têtes, CSP et interface

`Content-Security-Policy` restrictive (`default-src 'self'`, `base-uri 'none'`,
`object-src 'none'`, `frame-ancestors 'none'`), `X-Frame-Options: DENY`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
`Permissions-Policy` (géolocalisation/micro/camera/payment… désactivés),
`Cross-Origin-Opener-Policy`/`Resource-Policy`, HSTS (`max-age=31536000; includeSubDomains`)
dès que TLS est détecté. Le SPA React n'utilise **aucun** `dangerouslySetInnerHTML` : les
données utilisateur (noms, résumés de documents, motifs d'erreur) sont rendues comme du
texte, donc une charge utile `<img onerror=…>` téléversée ou saisie reste inerte
(`tests/security.test.js` vérifie les deux bouts : stockage brut + rendu échappé).

## 7. Journaux et audit

* Réduction automatique à l'émission : toute clé évoquant un secret
  (`password`, `token`, `cookie`, `csrf`, `secret`, `*_hash`, `salt`, `bearer`…) est masquée,
  dans les objets imbriqués comme dans les tableaux.
* Les chaînes libres ne peuvent pas être nettoyées de façon fiable : la règle d'or est
  « on ne journalise pas une valeur sensible ». Le test le matérialise : les paires
  `clé=valeur` et les jetons en query string sont masqués, un secret enfoui dans une phrase
  ne l'est pas — c'est au code appelant de ne pas l'écrire.
* IP et user-agent ne sont conservés que sous forme `ip:<empreinte>` / `ua:<empreinte>`
  (HMAC tronqué) : corrélables pour l'enquête, non réutilisables pour identifier.
* Les logs d'accès omettent la query string (elle peut porter un jeton) et les cookies.
* `audit_logs` est append-only par déclencheurs ; une suppression physique d'un compte ayant
  un historique est refusée — d'où la suppression logique.

## 8. Configuration et secrets

* Toute valeur dangereuse est un **échec de démarrage** en production (`exit 78`), pas un
  avertissement : CSRF désactivé, `SameSite=none` sans `Secure`, CORS `*`,
  `DISABLE_AUTH_FOR_TESTS`, secret absent/trop court/placeholder.
* Un secret fourni mais faible n'est **jamais** remplacé silencieusement par un secret généré :
  la génération en production est un choix explicite (`SECRET_ALLOW_GENERATED=1`).
* Les secrets générés sont écrits `0600` dans le volume (`DATA_DIR/.secret-*`) et ne sont
  jamais affichés ; le fichier de mot de passe administrateur généré obéit à la même règle et
  doit être lu puis supprimé.
* Le chargeur `.env` (`src/config/dotenv.js`) est borné : il ne remplace jamais l'environnement du processus, refuse un
  lien symbolique ou un chemin hors du projet, ignore les lignes invalides et ne journalise
  aucune valeur.

## 9. Chaîne de contrôle automatisée

| Outil | Rôle |
|---|---|
| `node scripts/lint.js` | syntaxe de tout le JS, import réel de 26 modules, motifs de secrets, primitives dangereuses, `console.*` dans `src/`, interpolation SQL, cohérence `.env.example` ↔ `process.env` utilisé, garde anti-`DROP` dans les migrations |
| `npm test` | 248 tests répartis sur 12 fichiers, exécutés contre une vraie instance en mémoire/dossier temporaire |
| `node scripts/security-audit.js` | secrets dans le dépôt et l'index Git, permissions des fichiers de secrets, gardes de configuration (exécution réelle de `loadConfig`), Docker (root, `:latest`, `no-new-privileges`), `npm audit` production |
| `node scripts/smoke-test.js` | 40 contrôles sur une **instance en cours d'exécution** : en-têtes, 401/403/404, CSRF opposable, changement de mot de passe forcé, SSRF, bouclage refusé, révocation après déconnexion, SPA et bundle |

## 10. Limites connues (à assumer, pas à masquer)

1. `node:sqlite` est marqué expérimental par Node : la surface utilisée est volontairement
   étroite (préparations, transactions, pragmas) pour réduire le risque de rupture.
2. Argon2id en pur JS est coûteux en CPU : sur un petit VPS, abaisser le débit d'authentification
   ou installer le binding natif (`npm i argon2`, détecté automatiquement).
3. Pas d'antivirus ni de sandbox d'exécution pour les fichiers : ils sont stockés et rendus
   inoffensifs, non analysés en profondeur ; l'analyse PDF est heuristique (texte simple).
4. Un seul nœud, base SQLite : la haute disponibilité et le partage de fichier entre répliques
   ne sont pas couverts (voir `VIDEO-AGENT.md` pour la mise à l'échelle des tâches longues).
5. Le rapport vidéo est **déclaratif** : il lit ce que l'en-tête du conteneur annonce. Un
   fichier peut mentir sur sa durée ou sa résolution sans que la phase A le détecte ; c'est
   pourquoi un résultat incohérent est mis en quarantaine et qu'aucun rendu n'est autorisé.
   La vérification par décodage réel, la lecture en continu (`Range`) et le transcodage
   restent à faire, dans un worker à part.
6. Le smoke test et les tests d'API ne remplacent pas un test navigateur (Playwright) : la
   chaîne de rendu React est vérifiée par des assertions structurelles et l'absence de
   `dangerouslySetInnerHTML`, pas par un DOM réel.
7. `npm audit` nécessite le registre ; hors ligne, l'audit le signale comme
   `ACTION NON EXÉCUTÉE` au lieu de conclure à tort.
