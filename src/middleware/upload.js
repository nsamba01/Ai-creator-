/**
 * Hardened multer wrapper.
 *
 * A malformed or truncated multipart body makes busboy throw a bare `Error`
 * ("Unexpected end of form"), and multer reports its own limits as
 * `MulterError`. Left alone, those surface as 500 — which is both
 * uninformative for the client and a signal that the API crashed. Every
 * parsing failure is therefore translated here into a 4xx `AppError`, while
 * genuine internal faults keep their 500 status.
 */
import { badRequest, tooLarge } from '../utils/errors.js';

/** multer error code -> [status, factory] */
const KNOWN_CODES = {
  LIMIT_FILE_SIZE: (cfg) =>
    tooLarge(`Fichier trop volumineux (maximum ${Math.round(cfg.uploads.maxBytes / 1024 / 1024)} Mo).`),
  LIMIT_FILE_SIZE_EXCEEDED: (cfg) => tooLarge('Fichier trop volumineux.'),
  LIMIT_UNEXPECTED_FILE: () => badRequest('Champ de téléversement inattendu : le champ doit s’appeler « file ».'),
  LIMIT_FILES: () => badRequest('Un seul fichier par requête est accepté.'),
  LIMIT_FIELD_KEY: () => badRequest('Nom de champ trop long.'),
  LIMIT_FIELD_VALUE: () => badRequest('Valeur de champ trop longue.'),
  LIMIT_FIELD_COUNT: () => badRequest('Trop de champs dans la requête.'),
  LIMIT_PART_COUNT: () => badRequest('Trop de parties dans la requête.'),
  LIMIT_HEADER_FIELD_SIZE: () => badRequest('En-tête de partie trop volumineux.'),
};

export function createUploadMiddleware(multerFactory, config) {
  const instance = multerFactory;
  function translate(err) {
    if (!err) return null;
    // Une erreur déjà typée (statut + code) vient de nos propres filtres : on la
    // laisse passer telle quelle, son message est plus précis que le nôtre.
    if (typeof err.status === 'number' && err.code) return err;
    const code = String(err.code ?? '');
    const mapped = KNOWN_CODES[code];
    if (mapped) return mapped(config);
    if (/multipart|malformed|unexpected end|boundary|abort/i.test(`${err.message} ${err.name}`)) {
      return badRequest('Corps multipart invalide ou tronqué (délimiteur, champ ou fichier manquant).');
    }
    return err; // erreur inconnue : le gestionnaire d'erreurs la traitera en 500
  }

  function wrap(mw) {
    return (req, res, next) => {
      mw(req, res, (err) => {
        const translated = translate(err);
        if (!translated) return next();
        return next(translated);
      });
    };
  }

  return {
    single: (field) => wrap(instance.single(field)),
    none: () => wrap(instance.none()),
  };
}
