/**
 * Video container header probe — pure JavaScript, no external binary.
 *
 * Scope (phase A de docs/VIDEO-AGENT.md) : lire UNIQUEMENT les métadonnées de
 * conteneur. Rien n'est décodé, aucune allocation n'est dimensionnée par une
 * taille déclarée, et l'extension du fichier n'est jamais crue : le conteneur
 * est identifié à partir des octets.
 *
 * Bornes volontaires (chacune est exercée par tests/videos.test.js) :
 *  - nombre maximal de boîtes/éléments visités : un fichier composé de millions
 *    de micro-boîtes ne peut pas Saturer le CPU ;
 *  - profondeur de récursion bornée ;
 *  - chaque lecture est vérifiée en bornes : une boîte tronquée interrompt la
 *    promenade, elle ne fait jamais remonter une exception jusqu'à la requête ;
 *  - aucune allocation à partir d'une taille du fichier : uniquement des vues.
 *
 * Conteneurs reconnus : ISO Base Media (mp4/mov/m4v), Matroska/WebM (EBML),
 * AVI (RIFF). Tout le reste est signalé comme conteneur non pris en charge.
 */

const MAX_CONTAINERS = 20_000;
const MAX_DEPTH = 12;

/** Arrêt de contrôle interne : « on s'arrête là, ce qu'on a est ce qu'on a ». */
class ProbeStop extends Error {}

/** Curseur borné sur un Buffer. */
class Cursor {
  constructor(buf, start = 0, end = buf.length) {
    this.buf = buf;
    this.pos = clamp(start, 0, buf.length);
    this.end = clamp(end, this.pos, buf.length);
  }

  get remaining() {
    return this.end - this.pos;
  }

  has(n) {
    return this.remaining >= n && n >= 0;
  }

  u8() {
    need(this.has(1));
    return this.buf[this.pos++];
  }

  u32() {
    need(this.has(4));
    const v = this.buf.readUInt32BE(this.pos);
    this.pos += 4;
    return v;
  }

  u32le() {
    need(this.has(4));
    const v = this.buf.readUInt32LE(this.pos);
    this.pos += 4;
    return v;
  }

  i32le() {
    need(this.has(4));
    const v = this.buf.readInt32LE(this.pos);
    this.pos += 4;
    return v;
  }

  /** BigInt : un timescale/duration au-delà de 2^32 ne doit pas être tronqué. */
  u64() {
    need(this.has(8));
    const v = this.buf.readBigUInt64BE(this.pos);
    this.pos += 8;
    return Number(v > 2n ** 53n ? 0n : v);
  }

  f32() {
    need(this.has(4));
    const v = this.buf.readFloatBE(this.pos);
    this.pos += 4;
    return v;
  }

  f64() {
    need(this.has(8));
    const v = this.buf.readDoubleBE(this.pos);
    this.pos += 8;
    return v;
  }

  /** latin1 : identité octet par octet (fourcc et identifiants de codec sont ASCII). */
  ascii(n) {
    need(this.has(n) && n > 0);
    const s = this.buf.subarray(this.pos, this.pos + n).toString('latin1');
    this.pos += n;
    return s;
  }

  skip(n) {
    need(this.has(n));
    this.pos += n;
  }

  seek(abs) {
    if (abs < this.pos || abs > this.end) throw new ProbeStop();
    this.pos = abs;
  }
}

function need(cond) {
  if (!cond) throw new ProbeStop();
}

function clamp(n, min, max) {
  if (!Number.isFinite(n)) return min;
  return Math.max(min, Math.min(max, n));
}

const FOURCC_PRINTABLE = /^[ -~]{4}$/;

/** Identifie le vrai conteneur à partir des premiers octets. */
export function sniffContainer(buf) {
  if (!buf || buf.length < 12) return { container: null, notes: ['contenu trop court pour être identifié'] };
  const tag4 = buf.subarray(4, 8).toString('latin1');
  if (tag4 === 'ftyp' || tag4 === 'styp' || tag4 === 'moov' || tag4 === 'mdat' || tag4 === 'free' || tag4 === 'wide' || tag4 === 'skip') {
    return { container: 'mp4', notes: [] };
  }
  if (buf[0] === 0x1a && buf[1] === 0x45 && buf[2] === 0xdf && buf[3] === 0xa3) return { container: 'matroska', notes: [] };
  if (buf.subarray(0, 4).toString('latin1') === 'RIFF' && buf.subarray(8, 12).toString('latin1') === 'AVI ') return { container: 'avi', notes: [] };
  if (buf.subarray(0, 4).toString('latin1') === 'OggS') return { container: null, notes: ['conteneur Ogg : en-têtes multiplexés, non sondés en phase A'] };
  if (buf.subarray(0, 3).toString('latin1') === 'FLV') return { container: null, notes: ['conteneur Flash Video non sondé'] };
  if (buf.subarray(4, 8).toString('latin1') === 'ftyx') return { container: null, notes: ['signature de conteneur inconnue (« ftyx »)'] };
  return { container: null, notes: ['signature de conteneur vidéo absente'] };
}

/* ------------------------------------------------------------------ ISO BMFF */

const MP4_MASTER = new Set(['moov', 'trak', 'mdia', 'minf', 'stbl', 'edts', 'mvex']);
/** Jamais descendu : charge utile média et tables d'offset (volume non borné). */
const MP4_SKIP = new Set(['mdat', 'free', 'skip', 'wide', 'pssh', 'sidx', 'moof', 'mfra', 'stco', 'co64', 'stsz', 'stsc', 'stss', 'stss', 'ctts', 'sdtp', 'uuid']);

const mp4State = () => ({
  containers: 0,
  brand: null,
  compatible: [],
  timescale: null,
  durationMs: null,
  codec: null,
  width: null,
  height: null,
  trackCount: 0,
  tracks: [],
  track: null,
  sawFtyp: false,
  sawMoov: false,
  fragmented: false,
  truncated: false,
  notes: [],
});

function walkMp4(cur, depth, st, endAt) {
  while (cur.pos < endAt) {
    if (st.containers++ > MAX_CONTAINERS) {
      st.notes.push('nombre maximal de boîtes atteint — lecture interrompue');
      return;
    }
    const boxStart = cur.pos;
    let size = cur.u32();
    const type = cur.ascii(4);
    let headerSize = 8;
    if (size === 1) {
      size = cur.u64();
      headerSize = 16;
    } else if (size === 0) {
      size = cur.end - boxStart; // « la boîte va jusqu'à la fin »
    }
    if (!Number.isFinite(size) || size < headerSize) {
      st.notes.push(`boîte ${printable(type) ? type : '?'} de taille incohérente — lecture arrêtée`);
      return;
    }
    // Une boîte peut dépasser la fenêtre lue : on borne, on n'alloue pas.
    const boxEnd = Math.min(boxStart + size, cur.end);
    if (boxStart + size > cur.end) st.truncated = true;
    const payload = boxStart + headerSize;

    if (type === 'ftyp') {
      st.sawFtyp = true;
      cur.seek(payload);
      st.brand = readFourcc(cur);
      if (cur.has(4)) st.minorVersion = cur.u32();
      const brands = [];
      while (brands.length < 16 && cur.pos + 4 <= boxEnd) {
        const b = readFourcc(cur);
        if (!b) break;
        brands.push(b);
      }
      st.compatible = brands;
    } else if (MP4_SKIP.has(type)) {
      if (type === 'moof') st.fragmented = true;
    } else if (MP4_MASTER.has(type) && depth < MAX_DEPTH) {
      const inner = new Cursor(cur.buf, payload, boxEnd);
      if (type === 'moov') st.sawMoov = true;
      if (type === 'trak') {
        st.trackCount += 1;
        st.track = { type: null, codec: null, width: null, height: null, durationMs: null, timescale: null, fps: null };
        st.tracks.push(st.track);
      }
      walkMp4(inner, depth + 1, st, boxEnd);
      if (type === 'trak') st.track = null;
    } else if (type === 'mvhd') {
      cur.seek(payload);
      const version = cur.u8();
      cur.skip(3);
      if (version === 1) {
        cur.skip(8);
        cur.skip(8);
        st.timescale = cur.u32();
        st.durationMs = toMs(cur.u64(), st.timescale);
      } else {
        cur.skip(4);
        cur.skip(4);
        st.timescale = cur.u32();
        st.durationMs = toMs(cur.u32(), st.timescale);
      }
    } else if (type === 'tkhd') {
      cur.seek(payload);
      const version = cur.u8();
      cur.skip(3);
      // Dimensions en fixe 16.16 en fin de structure : +76 (v0) / +88 (v1) depuis le
      // début de la boîte ; version + flags (4 octets) sont déjà consommés.
      cur.skip(version === 1 ? 84 : 72);
      const w = cur.u32() / 65536;
      const h = cur.u32() / 65536;
      if (st.track) {
        st.track.width = positive(w);
        st.track.height = positive(h);
        st.track.type = st.track.type ?? (st.track.width && st.track.height ? 'video' : null);
      }
    } else if (type === 'mdhd') {
      cur.seek(payload);
      const version = cur.u8();
      cur.skip(3);
      if (version === 1) {
        cur.skip(8);
        cur.skip(8);
        const ts = cur.u32();
        if (st.track) {
          st.track.timescale = positive(ts) ?? null;
          st.track.durationMs = toMs(cur.u64(), st.track.timescale);
        } else cur.u64();
      } else {
        cur.skip(4);
        cur.skip(4);
        const ts = cur.u32();
        if (st.track) {
          st.track.timescale = positive(ts) ?? null;
          st.track.durationMs = toMs(cur.u32(), st.track.timescale);
        } else cur.u32();
      }
    } else if (type === 'hdlr') {
      cur.seek(payload);
      cur.skip(8); // version/flags (4) + pre_defined (4)
      const handler = readFourcc(cur);
      if (st.track && handler) st.track.type = { vide: 'video', soun: 'audio', subt: 'subtitle', text: 'text', meta: 'timed-text' }[handler] ?? st.track.type;
    } else if (type === 'stsd') {
      cur.seek(payload);
      cur.skip(4); // version + flags
      const count = cur.u32();
      if (count > 0 && count < 1_000_000) {
        cur.skip(4); // taille de la première entrée
        const format = readFourcc(cur);
        if (format) {
          if (st.track && !st.track.codec) st.track.codec = format;
          if (!st.codec && looksLikeVideoCodec(format)) st.codec = format;
        }
      }
    } else if (type === 'stts') {
      // Débit d'images constant : premier (nombre d'échantillons, durée d'échantillon).
      cur.seek(payload);
      cur.skip(4);
      const entries = cur.u32();
      if (entries > 0 && entries < 100_000 && st.track?.timescale > 0) {
        cur.u32(); // sample_count
        const delta = cur.u32();
        if (delta > 0) st.track.fps = Math.round((st.track.timescale / delta) * 1000) / 1000;
      }
    }

    try {
      cur.seek(boxEnd);
    } catch {
      return;
    }
  }
}

function readFourcc(cur) {
  if (!cur.has(4)) return null;
  const s = cur.ascii(4);
  return FOURCC_PRINTABLE.test(s) ? s : null;
}

function printable(s) {
  return FOURCC_PRINTABLE.test(String(s ?? ''));
}

/** Chaîne ASCII courte et sans octet de contrôle : ce qui peut être exposé. */
function printableToken(s, max = 24) {
  const v = String(s ?? '').trim();
  return v.length > 0 && v.length <= max && /^[\x20-\x7e]+$/.test(v) ? v : '';
}

function toMs(raw, timescale) {
  const ts = Number(timescale);
  const d = Number(raw);
  if (!Number.isFinite(d) || d <= 0 || !Number.isFinite(ts) || ts <= 0) return null;
  return Math.round((d * 1000) / ts);
}

function positive(n) {
  const v = Number(n);
  if (!Number.isFinite(v) || v <= 0 || v > 65536) return null;
  return Math.round(v);
}

const VIDEO_CODECS = /^(avc|hev|hvc|vp[089]|av01|mjp2|mp4v|dx[0-9a-z]|DIVX|xvid|raw|png|jpeg|jpg)/i;
function looksLikeVideoCodec(fourcc) {
  return VIDEO_CODECS.test(String(fourcc ?? ''));
}

/**
 * Promène les boîtes ISO BMFF d'un tampon. `from` permet de partir d'une
 * fenêtre centrale (cas du `moov` écrit en fin de fichier).
 */
export function probeMp4(buf, { from = 0 } = {}) {
  const st = mp4State();
  let start = clamp(from, 0, Math.max(0, buf.length - 8));
  let end = buf.length;

  const headTag = buf.length >= start + 8 ? buf.subarray(start + 4, start + 8).toString('latin1') : '';
  if (headTag !== 'ftyp' && headTag !== 'moov' && headTag !== 'styp' && headTag !== 'mdat') {
    // Fenêtre quelconque : on localise une boîte « moov » dont la taille déclarée
    // tient dans la fenêtre (sinon la promenade partirait sur des octets média).
    const found = findBoxStart(buf, 'moov', start);
    if (found < 0) {
      st.notes.push('boîte « moov » introuvable dans la fenêtre lue');
      return st;
    }
    start = found;
    end = Math.min(buf.length, found + Math.max(8, buf.readUInt32BE(found)));
    st.sawMoov = true;
  }
  const cur = new Cursor(buf, start, end);
  try {
    walkMp4(cur, 0, st, end);
  } catch (err) {
    if (!(err instanceof ProbeStop)) throw err;
    st.notes.push('en-tête interrompu (fenêtre de lecture trop petite)');
  }
  const video = st.tracks.find((t) => t.type === 'video') ?? st.tracks.find((t) => t.width && t.height);
  if (video) {
    st.width = st.width ?? video.width;
    st.height = st.height ?? video.height;
    st.codec = st.codec ?? video.codec;
    st.fps = video.fps ?? null;
    if (st.durationMs === null) st.durationMs = video.durationMs;
  }
  return st;
}

/**
 * Localise le début d'une boîte à partir de son tag. Un fichier bien formé garde
 * les boîtes alignées sur 4 octets : ce parcours-là est tenté en premier. En cas
 * d'échec, une seconde passe octet par octet est autorisée, mais uniquement si la
 * taille déclarée de la boîte tient dans la fenêtre — ce qui écarte l'essentiel
 * des coïncidences dans les octets média.
 */
function findBoxStart(buf, type, from = 0) {
  const limit = Math.min(buf.length - 8, from + 2_000_000);
  const fits = (tagPos) => {
    if (tagPos < 4) return false;
    const size = buf.readUInt32BE(tagPos - 4);
    return size >= 8 && tagPos - 4 + size <= buf.length;
  };
  for (let i = from + 4; i <= limit; i += 4) {
    if (buf.subarray(i, i + 4).toString('latin1') === type && fits(i)) return i - 4;
  }
  for (let i = from + 4; i <= limit; i += 1) {
    if (buf.subarray(i, i + 4).toString('latin1') === type && fits(i)) return i - 4;
  }
  return -1;
}

/* ------------------------------------------------------------------ Matroska */

/** Entier EBML de taille variable : le bit de marque fait partie de l'identifiant. */
function readVint(buf, pos, { keepMarker = false } = {}) {
  if (pos >= buf.length || buf[pos] === 0) throw new ProbeStop();
  const first = buf[pos];
  let length = 1;
  let mask = 0x80;
  while (length <= 8 && !(first & mask)) {
    mask >>= 1;
    length += 1;
  }
  if (length > 8 || pos + length > buf.length) throw new ProbeStop();
  let value = keepMarker ? first : first & (0xff >>> length);
  for (let i = 1; i < length; i += 1) value = value * 256 + buf[pos + i];
  const payloadMax = 0xff >>> length;
  const unknown = !keepMarker && (first & payloadMax) === payloadMax && buf.subarray(pos + 1, pos + length).every((b) => b === 0xff);
  return { value, length, unknown };
}

const MKV_MASTER = new Set([0x1a45dfa3, 0x18538067, 0x1549a966, 0x1654ae6b, 0xae, 0xe0, 0xe1]);
/** Éléments binaires volumineux ou sans intérêt pour le sondage. */
const MKV_SKIP = new Set([0x1f43b675, 0x1c53bb6b, 0x23e38a, 0x2551c8, 0x1b538667, 0x7e7b]);
const MKV_TEXT = new Set([0x4282, 0x86, 0x22b59c]);
const MKV_UINT = new Set([0x2ad7b1, 0xb0, 0xba, 0x83, 0x2383e8, 0x4287, 0x9a]);
const MKV_FLOAT = new Set([0x4489]);

export function probeMatroska(buf) {
  const st = {
    containers: 0,
    doctype: null,
    timecodeScale: 1_000_000, // valeur par défaut de la spécification (ns)
    durationMs: null,
    width: null,
    height: null,
    codec: null,
    fps: null,
    trackCount: 0,
    tracks: [],
    truncated: false,
    notes: [],
  };

  const walk = (start, end, depth, track) => {
    const cur = new Cursor(buf, start, end);
    while (cur.remaining > 1) {
      if (st.containers++ > MAX_CONTAINERS) {
        st.notes.push('nombre maximal d’éléments atteint — lecture interrompue');
        return;
      }
      const here = cur.pos;
      let id;
      let size;
      try {
        const idVint = readVint(buf, here, { keepMarker: true });
        id = idVint.value;
        cur.skip(idVint.length);
        const sizeVint = readVint(buf, cur.pos);
        cur.skip(sizeVint.length);
        size = sizeVint.unknown ? cur.end - cur.pos : sizeVint.value;
      } catch {
        return; // en-tête d'élément incomplet : arrêt propre
      }
      const payload = cur.pos;
      const elemEnd = Math.min(cur.end, payload + Math.max(0, size));
      if (payload + size > cur.end) st.truncated = true;

      if (MKV_SKIP.has(id)) {
        cur.seek(elemEnd);
        continue;
      }
      if (MKV_MASTER.has(id) && depth < MAX_DEPTH) {
        if (id === 0xae) {
          st.trackCount += 1;
          const next = { type: null, codec: null, width: null, height: null, fps: null, name: null };
          st.tracks.push(next);
          walk(payload, elemEnd, depth + 1, next);
        } else {
          walk(payload, elemEnd, depth + 1, track);
        }
        cur.seek(elemEnd);
        continue;
      }

      try {
        if (MKV_TEXT.has(id)) {
          cur.seek(payload);
          const text = printableToken(cur.ascii(Math.min(size, 64)).replace(/\x00+$/, ''), 24);
          if (id === 0x4282) st.doctype = text || null;
          else if (id === 0x86 && text) {
            if (track && !track.codec) track.codec = text;
            if (!st.codec && (!track || track.type === 'video')) st.codec = text;
          } else if (id === 0x22b59c && track && !track.name) track.name = text || null;
        } else if (MKV_UINT.has(id)) {
          cur.seek(payload);
          let value = 0;
          const n = Math.min(size, 8);
          for (let i = 0; i < n; i += 1) value = value * 256 + cur.u8();
          if (id === 0x2ad7b1 && value > 0) st.timecodeScale = value;
          if (id === 0xb0 && track) track.width = positive(value);
          if (id === 0xba && track) track.height = positive(value);
          if (id === 0x83 && track) {
            track.type = value === 1 ? 'video' : value === 2 ? 'audio' : value === 3 ? 'subtitle' : 'other';
          }
          if (id === 0x2383e8 && value > 0 && track?.type === 'video') {
            // DefaultDuration est en nanosecondes par image.
            track.fps = Math.round((1_000_000_000 / value) * 1000) / 1000;
          }
        } else if (MKV_FLOAT.has(id)) {
          cur.seek(payload);
          let value = null;
          if (size === 4) value = cur.f32();
          else if (size === 8) value = cur.f64();
          else if (size === 10) value = cur.f64(); // 80 bits : approximation assumée, non bloquante
          if (value !== null && Number.isFinite(value) && value >= 0) st.durationMs = Math.round((value * st.timecodeScale) / 1_000_000);
        }
      } catch {
        // élément partiel : on arrête ce niveau
      }
      try {
        cur.seek(elemEnd);
      } catch {
        return;
      }
    }
  };

  try {
    walk(0, buf.length, 0, null);
  } catch (err) {
    if (!(err instanceof ProbeStop)) throw err;
  }
  const video = st.tracks.find((t) => t.type === 'video') ?? st.tracks.find((t) => t.width && t.height);
  if (video) {
    st.width = video.width;
    st.height = video.height;
    st.codec = video.codec ?? st.codec;
    st.fps = video.fps ?? null;
  }
  return st;
}

/* ----------------------------------------------------------------------- AVI */

export function probeAvi(buf) {
  const st = {
    containers: 0,
    brand: 'AVI',
    codec: null,
    width: null,
    height: null,
    durationMs: null,
    fps: null,
    totalFrames: null,
    microSecPerFrame: null,
    indexEntries: 0,
    trackCount: 0,
    tracks: [],
    track: null,
    truncated: false,
    notes: [],
  };

  const walk = (cur, end, depth) => {
    while (cur.pos + 8 <= end) {
      if (st.containers++ > MAX_CONTAINERS) {
        st.notes.push('nombre maximal de chunks atteint — lecture interrompue');
        return;
      }
      const start = cur.pos;
      const id = cur.ascii(4);
      const size = cur.u32le();
      const payload = cur.pos;
      if (size < 0) return;
      const chunkEnd = Math.min(end, payload + size + (size % 2));
      if (payload + size > end) st.truncated = true;

      if (id === 'LIST' || id === 'hdrl' || id === 'movi' || id === 'strl' || id === 'rec ') {
        if (depth < MAX_DEPTH) {
          const inner = new Cursor(buf, payload + (id === 'LIST' ? 4 : 0), chunkEnd);
          walk(inner, chunkEnd, depth + 1);
        }
      } else {
        try {
          if (id === 'avih') {
            // AVIMAINHEADER : dwMicroSecPerFrame à 0, dwWidth à 32, dwHeight à 36.
            cur.seek(payload);
            st.microSecPerFrame = cur.u32le();
            if (st.microSecPerFrame > 0) st.fps = Math.round((1_000_000 / st.microSecPerFrame) * 1000) / 1000;
            cur.seek(payload + 32);
            st.width = positive(cur.u32le());
            st.height = positive(cur.u32le());
          } else if (id === 'strh') {
            // AVISTREAMHEADER : fccType à 0, dwScale 20, dwRate 24, dwLength 32,
            // dwSampleSize 48. Valeurs lues directement : un seul « skip » faux suffit
            // à décaler toute la structure, d'où les offsets nommés.
            if (size < 52) throw new ProbeStop();
            cur.seek(payload);
            const type = cur.ascii(4).trim();
            cur.seek(payload + 16);
            const initial = cur.u32le();
            const scale = cur.u32le();
            const rate = cur.u32le();
            cur.seek(payload + 32);
            const length = cur.u32le();
            cur.seek(payload + 48);
            const sampleSize = cur.u32le();
            st.trackCount += 1;
            const track = {
              type: type === 'vids' ? 'video' : type === 'auds' ? 'audio' : type === 'txts' ? 'subtitle' : type.toLowerCase() || null,
              codec: null,
              width: null,
              height: null,
              fps: null,
              durationMs: null,
              frames: length > 0 ? length : null,
              sampleSize: positive(sampleSize),
              initialFrames: positive(initial),
            };
            if (type === 'vids' && rate > 0 && scale > 0) {
              track.fps = Math.round((rate / scale) * 1000) / 1000;
              if (length > 0) track.durationMs = Math.round((length * scale * 1000) / rate);
            }
            st.tracks.push(track);
            st.track = track;
            if (type === 'vids') {
              if (st.fps === null) st.fps = track.fps;
              if (st.durationMs === null) st.durationMs = track.durationMs;
              if (st.totalFrames === null) st.totalFrames = track.frames;
              if (st.durationMs === null && st.microSecPerFrame > 0 && track.frames) {
                st.durationMs = Math.round((st.microSecPerFrame * track.frames) / 1000);
              }
            }
          } else if (id === 'strf') {
            if (size < 40) throw new ProbeStop();
            cur.seek(payload);
            const biSize = cur.u32le();
            const w = cur.i32le();
            const h = cur.i32le();
            cur.skip(4); // biPlanes + biBitCount
            const fourcc = cur.has(4) ? readFourcc(cur) : null;
            if (biSize >= 40) {
              if (!st.width && w > 0) st.width = positive(w);
              if (!st.height && h !== 0) st.height = positive(Math.abs(h));
              if (st.track) {
                st.track.width = positive(w);
                st.track.height = positive(Math.abs(h));
              }
            }
            if (fourcc && st.track && !st.track.codec) {
              st.track.codec = fourcc;
              st.codec = st.codec ?? fourcc;
            }
          } else if (id === 'idx1') {
            st.indexEntries = Math.floor(size / 16);
          }
        } catch {
          // chunk tronqué ou déclaration aberrante : arrêt propre
        }
      }
      try {
        cur.seek(Math.max(chunkEnd, start + 8));
      } catch {
        return;
      }
    }
  };

  if (buf.length >= 12) {
    const cur = new Cursor(buf, 12, buf.length); // après « RIFF » + taille + « AVI »
    try {
      walk(cur, buf.length, 0);
    } catch (err) {
      if (!(err instanceof ProbeStop)) throw err;
    }
  }
  const video = st.tracks.find((t) => t.type === 'video');
  if (video?.codec && !st.codec) st.codec = video.codec;
  if (video?.width && !st.width) {
    st.width = video.width;
    st.height = video.height ?? st.height;
  }
  return st;
}

/* ------------------------------------------------------------------ synthèse */

/**
 * Sonde une fenêtre de tête (et, le cas échéant, une fenêtre de queue pour les
 * MP4 dont le `moov` est écrit en fin de fichier).
 *
 * @param {Buffer} head  premiers octets du fichier
 * @param {Buffer|null} tail  derniers octets, ou null
 * @param {{maxDurationMs?: number, bytes?: number}} opts
 */
export function probeVideoWindows(head, tail = null, opts = {}) {
  const sniff = sniffContainer(head);
  if (!sniff.container) {
    return { ok: false, errorCode: 'VIDEO_UNSUPPORTED_CONTAINER', container: null, notes: [...sniff.notes], streams: [] };
  }
  let raw;
  let parser;
  if (sniff.container === 'mp4') {
    raw = probeMp4(head);
    parser = 'iso-bmff';
    if (!raw.sawMoov && tail && tail.length >= 12) {
      const retried = probeMp4(tail);
      if (retried.sawMoov) raw = retried;
      else raw.notes.push(...retried.notes.filter((n) => !raw.notes.includes(n)));
    }
  } else if (sniff.container === 'matroska') {
    raw = probeMatroska(head);
    parser = 'ebml';
  } else {
    raw = probeAvi(head);
    parser = 'riff';
  }

  const notes = [...(raw.notes ?? [])];
  if (raw.truncated) notes.push('fenêtre de lecture insuffisante : certaines structures n’ont pas pu être lues');
  const durationMs = Number.isFinite(raw.durationMs) && raw.durationMs >= 0 ? Math.round(raw.durationMs) : null;
  const width = positive(raw.width ?? null);
  const height = positive(raw.height ?? null);
  const streams = (raw.tracks ?? [])
    .slice(0, 32)
    .map((t) => ({
      type: t.type ?? (t.width && t.height ? 'video' : 'unknown'),
      codec: t.codec ?? null,
      width: t.width ?? null,
      height: t.height ?? null,
      fps: t.fps ?? null,
      durationMs: t.durationMs ?? null,
      name: t.name ?? null,
    }));

  // Ce qui a été lu reste acquis : un refus de durée ou de géométrie ne doit pas effacer le
  // conteneur, le codec ou les pistes déjà identifiés — sinon le rapport de quarantaine ne
  // dirait plus rien à l’administrateur qui doit trancher, et la ligne prétendrait n’avoir
  // été sondée par personne.
  const fps = Number.isFinite(raw.fps) && raw.fps > 0 && raw.fps <= 1000 ? Math.round(raw.fps * 1000) / 1000 : null;
  const fileSize = Number.isFinite(Number(opts.bytes)) && Number(opts.bytes) > 0 ? Number(opts.bytes) : null;
  const bitrateBps = fileSize && durationMs ? Math.round((fileSize * 8) / (durationMs / 1000)) : null;
  const facts = {
    container: sniff.container,
    brand: raw.brand ?? raw.doctype ?? null,
    compatible: raw.compatible ?? [],
    codec: raw.codec ?? null,
    parser,
    doctype: raw.doctype ?? null,
    durationMs,
    width,
    height,
    fps,
    bitrateBps,
    trackCount: raw.trackCount ?? streams.length,
    indexEntries: raw.indexEntries ?? null,
    fragmented: Boolean(raw.fragmented),
    truncated: Boolean(raw.truncated),
    streams,
  };

  if (durationMs !== null && opts.maxDurationMs && durationMs > opts.maxDurationMs) {
    return {
      ...facts,
      ok: false,
      errorCode: 'VIDEO_DURATION_EXCEEDED',
      notes: [...notes, `durée déclarée ${Math.round(durationMs / 1000)} s, limite ${Math.round(opts.maxDurationMs / 1000)} s`],
    };
  }

  const declaredBad = (raw.width != null && width === null) || (raw.height != null && height === null);
  if (declaredBad) {
    return { ...facts, ok: false, errorCode: 'VIDEO_DIMENSIONS_INVALID', notes: [...notes, 'dimensions déclarées incohérentes'] };
  }

  const hasSignal = durationMs !== null || width !== null || raw.codec != null || streams.length > 0;
  if (!hasSignal) {
    notes.push('aucune métadonnée exploitable : installez ffprobe (VIDEO_USE_FFPROBE=1) pour un sondage complet');
    return { ...facts, ok: false, errorCode: 'VIDEO_HEADER_INCOMPLETE', notes };
  }

  return { ...facts, ok: true, errorCode: null, notes };
}

export const __internals = { Cursor, ProbeStop, readVint, MAX_CONTAINERS, MAX_DEPTH, findBoxStart };
