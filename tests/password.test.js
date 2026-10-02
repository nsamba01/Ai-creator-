/**
 * Password handling: Argon2id hashing, verification, rehash policy, strength
 * rules, temporary password generation. No plaintext ever leaves the process.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { describe as nodeDescribe, it } from 'node:test';
import { argon2id } from '@noble/hashes/argon2';
import { encodeHash, parseHash, hashPassword, verifyPassword, assertPasswordPolicy, estimateEntropyBits, foldCommon } from '../src/services/password.service.js';
import { randomTempPassword, randomBase64Url, randomHex, sha256Hex, hmacHex, safeEqual } from '../src/utils/crypto.js';

const PARAMS = { memoryCost: 8192, timeCost: 1, parallelism: 1, hashLength: 32 };

nodeDescribe('hachage Argon2id', () => {
  it('produit un hash au format PHC et ne contient jamais le mot de passe', async () => {
    const pwd = 'Clair-De-Lune-2026!';
    const { hash, algorithm, params } = await hashPassword(pwd, PARAMS);
    assert.equal(algorithm, 'argon2id', 'implémentation portable tant qu’aucune binding native n’est installée');
    assert.match(hash, /^\$argon2id\$v=19\$m=8192,t=1,p=1\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/);
    assert.ok(!hash.includes(pwd), 'le mot de passe n’apparaît pas dans le hash');
    assert.deepEqual(params, { memoryCost: 8192, timeCost: 1, parallelism: 1 });
  });

  it('sale aléatoirement : deux hachages du même mot de passe diffèrent', async () => {
    const a = await hashPassword('Identique-2026!', PARAMS);
    const b = await hashPassword('Identique-2026!', PARAMS);
    assert.notEqual(a.hash, b.hash);
    assert.equal((await verifyPassword('Identique-2026!', a.hash, PARAMS)).ok, true);
    assert.equal((await verifyPassword('Identique-2026!', b.hash, PARAMS)).ok, true);
  });

  it('refuse un mot de passe vide ou non textuel', async () => {
    for (const bad of ['', null, undefined, 42, {}]) {
      await assert.rejects(() => hashPassword(bad, PARAMS), /invalide/, `${JSON.stringify(bad)}`);
    }
  });

  it('normalise en NFKC (les variantes se conforment)', async () => {
    const composed = await hashPassword('café-2026!é', PARAMS);
    const decomposed = 'café-2026!é'; // e + combining acute
    assert.notEqual(composed, decomposed, 'les chaînes brutes diffèrent');
    const out = await verifyPassword(decomposed, composed.hash, PARAMS);
    assert.equal(out.ok, true, 'la comparaison se fait sur la forme normalisée');
  });

  it('reconnait un échec sans distinction de cause', async () => {
    const { hash } = await hashPassword('Bon-2026!motdepasse', PARAMS);
    for (const wrong of ['Mauvais-2026!motdepasse', '', 'bon-2026!motdepasse', 'Bon-2026!motdepassee']) {
      const out = await verifyPassword(wrong, hash, PARAMS);
      assert.equal(out.ok, false, `rejeté : ${wrong}`);
      assert.equal(out.reason, undefined, 'aucun motif détaillé renvoyé');
    }
  });

  it('demande un réhachage quand les paramètres ont changé', async () => {
    const { hash } = await hashPassword('Rehash-2026!moi', PARAMS);
    const same = await verifyPassword('Rehash-2026!moi', hash, PARAMS);
    assert.equal(same.needsRehash, false, 'paramètres identiques : rien à faire');
    const stronger = await verifyPassword('Rehash-2026!moi', hash, { ...PARAMS, memoryCost: 65536, timeCost: 3 });
    assert.equal(stronger.ok, true, 'le mot de passe reste valide');
    assert.equal(stronger.needsRehash, true, 'mais le hash doit être renforcé');
  });

  it('rejette un hash stocké corrompu ou d’un autre algorithme', async () => {
    for (const junk of ['', 'pas-un-hash', '$argon2id$v=19$m=1,t=1,p=1$$', '$2b$12$abcdefghij', '$argon2i$v=19$m=8192,t=1,p=1$c2FsdA$ZGln']) {
      const out = await verifyPassword('X-2026!yz', junk, PARAMS);
      assert.equal(out.ok, false, `rejeté : ${junk}`);
      assert.equal(out.needsRehash, true, 'et à réémettre');
    }
  });

  it('encode et relit un PHC complet, sel et empreinte compris', () => {
    const salt = crypto.randomBytes(16);
    const digest = crypto.randomBytes(32);
    const hash = encodeHash({ salt, digest, memoryCost: 19456, timeCost: 3, parallelism: 2 });
    const parsed = parseHash(hash);
    assert.equal(parsed.algo, 'argon2id');
    assert.equal(parsed.memoryCost, 19456);
    assert.equal(parsed.timeCost, 3);
    assert.equal(parsed.parallelism, 2);
    assert.deepEqual(Buffer.from(parsed.salt, 'base64'), salt);
    assert.deepEqual(Buffer.from(parsed.digest, 'base64'), digest);
    assert.equal(parseHash('rdfjïkghd'), null, 'une entrée invalide ne produit aucun algorithme');
  });

  it('utilise bien argon2id (et non argon2i/d) avec les paramètres demandés', async () => {
    const { hash } = await hashPassword('Controle-Algo-2026!', PARAMS);
    const parsed = parseHash(hash);
    assert.equal(parsed.algo, 'argon2id');
    // Le digest recalculé localement doit correspondre octet pour octet.
    const raw = argon2id(new TextEncoder().encode('Controle-Algo-2026!'), Buffer.from(parsed.salt, 'base64'), {
      m: parsed.memoryCost,
      t: parsed.timeCost,
      p: parsed.parallelism,
      dkLen: 32,
    });
    assert.equal(Buffer.from(raw).toString('base64'), parsed.digest);
  });
});

nodeDescribe('politique de mot de passe', () => {
  const base = { minLength: 12 };
  const reasons = (pwd, opts = base) => {
    try {
      assertPasswordPolicy(pwd, opts);
      return null;
    } catch (e) {
      return (e.details?.reasons ?? []).join(' | ');
    }
  };

  it('refuse trop court, trop long et caractères de contrôle', () => {
    assert.match(reasons('Court!1'), /au moins 12/);
    assert.match(reasons('A'.repeat(129) + '1!'), /au plus 128/);
    assert.match(reasons('Ligne\tavec\nsaut 2026!'), /caractère de contrôle|contrôle/);
    assert.equal(reasons('Zephyr-Cloche-2026!'), null, 'un mot de passe conforme passe');
    const err = (() => {
      try {
        assertPasswordPolicy('court', base);
      } catch (e) {
        return e;
      }
    })();
    assert.equal(err.status, 400);
    assert.ok(Array.isArray(err.details.reasons) && err.details.reasons.length >= 1, 'les motifs sont détaillés côté client');
    assert.ok(err.details.minLength === 12);
    assert.ok(!err.message.includes('court'), 'le message générique ne répète pas la valeur soumise');
  });

  it('refuse les mots de passe courants, même déguisés', () => {
    for (const weak of ['Password1', 'motdepasse', 'MOTDEPASSE', 'azerty123', 'ChangeMe', 'princesamba1', 'P@ssw0rd-2026', 'Mot_De_Passe_123']) {
      assert.match(reasons(weak, { minLength: 12 }) ?? '', /trop courant/, `${weak} aurait dû être refusé`);
    }
    assert.equal(foldCommon('P@ssw0rd-2026'), 'password', 'le repli canonique est bien testé');
  });

  it('exige trois classes de caractères et proscrit les répétitions', () => {
    assert.match(reasons('juste_des_lettres_longues'), /classes/);
    assert.match(reasons('1234567890123456'), /classes/);
    assert.match(reasons('AAAAaaa1111!!!!'), /consécutifs/);
    assert.equal(reasons('Zephyr-Cloche-2026!'), null);
  });

  it('interdit l’identité dans le mot de passe (contexte fourni par l’appelant)', () => {
    const ctx = { minLength: 12, context: ['alice', 'alice@test.local'] };
    assert.match(reasons('Alice-Test-Local-1!', ctx) ?? '', /ne doit pas contenir/);
    assert.equal(reasons('Zephyr-Cloche-2026!', ctx), null);
  });

  it('ne casse pas la ponctuation légitime en cherchant le dictionnaire', () => {
    assert.equal(reasons('Trois-Clos-Marins-Ventent-99!'), null, 'une longue phrase de passe reste acceptée');
    assert.match(reasons('bonjour-2026!') ?? '', /trop courant/, 'la salutation seule est connue');
  });

  it('calcule une entropie croissante avec la longueur et le jeu de caractères', () => {
    const short = estimateEntropyBits('aA1!');
    const long = estimateEntropyBits('aA1!bB2@');
    assert.ok(long > short, 'plus long = plus d’entropie');
    assert.equal(estimateEntropyBits(''), 0);
    assert.equal(estimateEntropyBits('abcdef'), Math.round(6 * Math.log2(26)));
    assert.ok(estimateEntropyBits('Zephyr-Cloche-2026!') > 80, 'un mot de passe conforme dépasse 80 bits');
  });
});

nodeDescribe('mots de passe provisoires et matériaux', () => {
  it('génère 16 caractères couvrant les quatre classes, sans ambiguïté', () => {
    const seen = new Set();
    for (let i = 0; i < 60; i += 1) {
      const p = randomTempPassword(16);
      assert.equal(p.length, 16);
      assert.match(p, /[a-z]/);
      assert.match(p, /[A-Z]/);
      assert.match(p, /[0-9]/);
      assert.match(p, /[^A-Za-z0-9]/);
      assert.ok(!/[Il1O0]/.test(p), 'aucun caractère ambigu (I l 1 O 0 exclus du jeu)');
      seen.add(p);
    }
    assert.ok(seen.size > 55, 'les générations sont distinctes');
  });

  it('respecte la politique interne et ne réutilise jamais la même valeur', () => {
    const a = randomTempPassword(16);
    assert.doesNotThrow(() => assertPasswordPolicy(a, { minLength: 12, context: [] }));
  });

  it('produit des jetons URL-sûrs et non prédictibles', () => {
    const set = new Set();
    for (let i = 0; i < 200; i += 1) {
      const t = randomBase64Url(32);
      assert.match(t, /^[A-Za-z0-9_-]+$/, 'aucun caractère à échapper en URL ou en cookie');
      assert.ok(t.length >= 32, 'au moins 32 caractères → ≥ 128 bits');
      set.add(t);
    }
    assert.equal(set.size, 200, 'aucune collision');
    assert.match(randomHex(16), /^[0-9a-f]{32}$/, 'variante hexadécéimale stable');
  });

  it('HMAC et SHA-256 sont stables, et la comparaison est à temps constant', () => {
    assert.equal(sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    assert.equal(hmacHex('k', 'v'), hmacHex('k', 'v'));
    assert.notEqual(hmacHex('k', 'v'), hmacHex('k2', 'v'));
    assert.equal(safeEqual('abc', 'abc'), true);
    assert.equal(safeEqual('abc', 'abd'), false);
    assert.equal(safeEqual('abc', ''), false);
    assert.equal(safeEqual(null, null), false, 'les valeurs non textuelles ne correspondent jamais');
  });
});
