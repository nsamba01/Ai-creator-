/**
 * Read-only, minimal ZIP container parser (STORE + DEFLATE).
 *
 * Used by the DOCX/XLSX readers. Deliberately tiny and defensive:
 *  - only the central directory is trusted (local headers can lie);
 *  - entry count, per-entry and total uncompressed sizes are capped, so a
 *    "zip bomb" document cannot exhaust memory;
 *  - no extraction to disk, no symlink handling => no path traversal at all.
 */
import zlib from 'node:zlib';

const EOCD_SIG = 0x06054b50;
const CD_SIG = 0x02014b50;

export class ZipError extends Error {
  constructor(msg) {
    super(msg);
    this.name = 'ZipError';
  }
}

export function readZip(buffer, { maxEntries = 2000, maxEntryBytes = 64 * 1024 * 1024, maxTotalBytes = 128 * 1024 * 1024 } = {}) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 22) throw new ZipError('Archive trop petite pour être un ZIP.');
  const sig = buffer.readUInt32LE(0);
  if (buffer.subarray(0, 2).toString('latin1') !== 'PK') throw new ZipError('Signature ZIP absente.');
  if (sig === 0x08074b50) throw new ZipError('Archive ZIP chiffrée non prise en charge.');

  // Locate End Of Central Directory record in the last 64 KiB + 22 bytes.
  const scanStart = Math.max(0, buffer.length - 22 - 0xffff);
  let eocd = -1;
  for (let i = buffer.length - 22; i >= scanStart; i -= 1) {
    if (buffer.readUInt32LE(i) === EOCD_SIG) {
      eocd = i;
      break;
    }
  }
  if (eocd === -1) throw new ZipError('Fin de répertoire central introuvable (archive tronquée ou ZIP64).');

  const entryCount = buffer.readUInt16LE(eocd + 10);
  const cdSize = buffer.readUInt32LE(eocd + 12);
  const cdOffset = buffer.readUInt32LE(eocd + 16);
  if (entryCount === 0xffff || cdOffset === 0xffffffff) throw new ZipError('ZIP64 non pris en charge par ce lecteur.');
  if (entryCount > maxEntries) throw new ZipError(`Trop d'entrées (${entryCount}).`);
  if (cdOffset + cdSize > buffer.length) throw new ZipError('Répertoire central hors fichier.');

  const entries = new Map();
  let total = 0;
  let p = cdOffset;
  for (let i = 0; i < entryCount; i += 1) {
    if (p + 46 > buffer.length || buffer.readUInt32LE(p) !== CD_SIG) break;
    const flags = buffer.readUInt16LE(p + 8);
    const method = buffer.readUInt16LE(p + 10);
    const compSize = buffer.readUInt32LE(p + 20);
    const uncompSize = buffer.readUInt32LE(p + 24);
    const nameLen = buffer.readUInt16LE(p + 28);
    const extraLen = buffer.readUInt16LE(p + 30);
    const commentLen = buffer.readUInt16LE(p + 32);
    const localOffset = buffer.readUInt32LE(p + 42);
    const name = buffer.subarray(p + 46, p + 46 + nameLen).toString('utf8');
    p += 46 + nameLen + extraLen + commentLen;

    if (name.endsWith('/')) continue; // directory entry
    if (method !== 0 && method !== 8) throw new ZipError(`Méthode de compression non supportée (${method}) pour ${name}.`);
    if (uncompSize > maxEntryBytes) throw new ZipError(`Entrée décompressée trop volumineuse : ${name}.`);
    total += uncompSize;
    if (total > maxTotalBytes) throw new ZipError('Volume décompressé total trop important (zip bomb ?).');

    if (localOffset + 30 > buffer.length || buffer.readUInt32LE(localOffset) !== 0x04034b50) {
      throw new ZipError(`En-tête local invalide pour ${name}.`);
    }
    const localNameLen = buffer.readUInt16LE(localOffset + 26);
    const localExtraLen = buffer.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + localNameLen + localExtraLen;
    const encrypted = (flags & 0x1) === 0x1;
    if (encrypted) throw new ZipError(`Entrée chiffrée : ${name}.`);
    let size = compSize;
    if (size === 0 && uncompSize === 0) size = 0; // empty file, may be descriptor-based
    const data = buffer.subarray(dataStart, dataStart + (compSize || uncompSize));

    entries.set(name, {
      name,
      method,
      size: uncompSize,
      compressedSize: compSize,
      read() {
        if (method === 0) return Buffer.from(data);
        return zlib.inflateRawSync(data, { maxOutputLength: Math.max(uncompSize * 2, 4 * 1024 * 1024) });
      },
    });
  }

  return {
    names: [...entries.keys()],
    has: (n) => entries.has(n),
    get(name) {
      const e = entries.get(name);
      return e ? e.read() : null;
    },
    entries: [...entries.values()].map((e) => ({ name: e.name, size: e.size, method: e.method })),
  };
}

export default readZip;
