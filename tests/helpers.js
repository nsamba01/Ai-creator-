/**
 * Test harness: boots a real HTTP server on an ephemeral port with an isolated
 * SQLite database, and provides a cookie-aware client. Nothing is mocked at
 * the HTTP layer: requests go through the whole middleware chain.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before } from 'node:test';

import { loadConfig } from '../src/config/env.js';
import { createRuntime } from '../src/runtime.js';
import { createApp } from '../src/app.js';
import { hashPassword } from '../src/services/password.service.js';
import * as usersRepo from '../src/repositories/users.repo.js';

export function makeTempDir(prefix = 'ps-ai-test-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

export async function boot({ withAdmin = true, adminPassword = 'Sup3r-Secret-Initial!', extraConfig = {}, bootstrap = false, port = 0 } = {}) {
  const dir = makeTempDir();
  const config = loadConfig(
    {
      NODE_ENV: 'test',
      LOG_LEVEL: 'silent',
      LOG_JSON: '0',
      DATA_DIR: dir,
      BOOTSTRAP_ADMIN: bootstrap ? '1' : '0',
      // Les tests fonctionnels ne doivent pas dépendre des compteurs de débit :
      // ils sont relevés ici, et testés explicitement dans security.test.js.
      API_RATE_LIMIT_PER_MIN: String(extraConfig.API_RATE_LIMIT_PER_MIN ?? 100000),
      AUTH_RATE_LIMIT_PER_MIN: String(extraConfig.AUTH_RATE_LIMIT_PER_MIN ?? 100000),
      URL_RATE_LIMIT_PER_MIN: String(extraConfig.URL_RATE_LIMIT_PER_MIN ?? 100000),
      ...extraConfig,
    },
    {
      DATA_DIR: dir,
      DB_PATH: path.join(dir, 'app.db'),
      UPLOAD_DIR: path.join(dir, 'uploads'),
      PORT: String(port ?? 0),
      HOST: '127.0.0.1',
      SESSION_SECRET: 'a'.repeat(48),
      STATE_SECRET: 'b'.repeat(48),
      BOOTSTRAP_ADMIN_PASSWORD: 'Env-Bootstrap-Pass-2026!',
      BOOTSTRAP_ADMIN_EMAIL: 'root@example.com',
      ...extraConfig,
    },
  );

  const runtime = createRuntime({ config });
  if (bootstrap) {
    const { bootstrapAdmin } = await import('../src/services/bootstrap.service.js');
    await bootstrapAdmin({ db: runtime.db, config, audit: runtime.audit, rbac: runtime.rbac });
  }
  const created = [];
  let standardPassword = null;
  if (withAdmin) {
    const { hash, params } = await hashPassword(adminPassword, config.password.argon2);
    const admin = usersRepo.createUser(runtime.db, {
      email: 'admin@test.local',
      username: 'admin',
      displayName: 'Admin Test',
      passwordHash: hash,
      hashParams: params,
      mustChangePassword: false,
      status: 'active',
    });
    runtime.rbac.assignRoles({ actorUserId: admin.id, userId: admin.id, roleNames: ['ADMIN'] });
    created.push(admin);

    const userPwd = 'User-Standard-2026!';
    const uh = await hashPassword(userPwd, config.password.argon2);
    const user = usersRepo.createUser(runtime.db, {
      email: 'alice@test.local',
      username: 'alice',
      displayName: 'Alice',
      passwordHash: uh.hash,
      hashParams: uh.params,
      mustChangePassword: false,
      status: 'active',
    });
    runtime.rbac.assignRoles({ actorUserId: admin.id, userId: user.id, roleNames: ['USER'] });
    created.push(user);
    standardPassword = userPwd;
  }

  const app = createApp(runtime);
  // Un port explicite n'est demandé que par les tests qui doivent rappeler
  // l'application par TCP (analyse d'URL) ; sinon on laisse l'OS choisir.
  const requestedPort = Number(port ?? 0);
  const server = await new Promise((resolve, reject) => {
    const s = app.listen(requestedPort, '127.0.0.1', () => {
      s.off('error', reject);
      resolve(s);
    });
    s.on('error', (err) => reject(new Error(`écoute impossible sur le port ${requestedPort} : ${err.message}`)));
  });
  const base = `http://127.0.0.1:${server.address().port}`;

  const ctx = {
    dir,
    config,
    runtime,
    app,
    server,
    base,
    users: { admin: created[0], user: created[1] },
    standardPassword,
    client: () => makeClient(base),
    async close() {
      await new Promise((resolve) => server.close(resolve));
      runtime.close();
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
  return ctx;
}

/** Installs before/after hooks for a booted app. */
export function useApp(options = {}) {
  const holder = { current: null };
  before(async () => {
    holder.current = await boot(options);
  });
  after(async () => {
    await holder.current?.close();
  });
  return holder;
}

export function makeClient(base) {
  const jar = new Map();
  let csrf = null;

  function cookieHeader() {
    return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }

  function absorb(res) {
    const raw = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    for (const line of raw) {
      const [pair] = String(line).split(';');
      const idx = pair.indexOf('=');
      const name = pair.slice(0, idx).replace(/^__Host-/, '');
      const value = pair.slice(idx + 1);
      if (/=;|Max-Age=0|Expires=Thu, 01 Jan 1970/.test(String(line)) || value === '') jar.delete(name);
      else jar.set(name, value);
      if (name === 'ps_csrf') csrf = value;
    }
  }

  async function request(method, path, { body, headers = {}, form, noCsrf = false, rawText = false } = {}) {
    const opts = { method, headers: { ...headers }, redirect: 'manual' };
    if (jar.size) opts.headers.cookie = cookieHeader();
    if (body !== undefined) {
      opts.headers['content-type'] = 'application/json';
      opts.body = JSON.stringify(body);
    } else if (form !== undefined) {
      opts.body = form;
    }
    if (!['GET', 'HEAD'].includes(method) && csrf && !noCsrf) opts.headers['x-csrf-token'] = csrf;
    const res = await fetch(base + path, opts);
    absorb(res);
    const text = await res.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    return {
      status: res.status,
      headers: res.headers,
      ok: res.ok,
      body: rawText ? text : json ?? text,
      text,
      cookies: () => cookieHeader(),
      csrf: () => csrf,
    };
  }

  return {
    get: (p, o) => request('GET', p, o),
    post: (p, body, o) => request('POST', p, { ...o, body }),
    put: (p, body, o) => request('PUT', p, { ...o, body }),
    patch: (p, body, o) => request('PATCH', p, { ...o, body }),
    del: (p, o) => request('DELETE', p, o),
    head: (p, o) => request('HEAD', p, o),
    request,
    jar,
    setCookie: (k, v) => jar.set(k, v),
    setCsrf: (v) => {
      csrf = v;
    },
    getCsrf: () => csrf,
    async login(identifier, password) {
      const res = await request('POST', '/api/auth/login', { body: { identifier, password } });
      return res;
    },
  };
}

/** Builds a minimal but valid DOCX/XLSX payload without any dependency. */
export function buildDocx(paragraphs) {
  const body = paragraphs
    .map((p, i) => {
      const style = p.style ? `<w:pPr><w:pStyle w:val="${p.style}"/></w:pPr>` : '';
      return `<w:p>${style}<w:r><w:t xml:space="preserve">${escapeXml(p.text)}</w:t></w:r></w:p>`;
    })
    .join('');
  const document = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>${body}<w:sectPr/></w:body></w:document>`;
  const contentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`;
  const rels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`;
  const docRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="ext1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.com/report" TargetMode="External"/>
</Relationships>`;
  const core = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">
<dc:creator>PrinceNsamba Tests</dc:creator><dc:title>Rapport de test</dc:title></cp:coreProperties>`;
  return zip([
    ['[Content_Types].xml', contentTypes],
    ['_rels/.rels', rels],
    ['word/document.xml', document],
    ['word/_rels/document.xml.rels', docRels],
    ['docProps/core.xml', core],
  ]);
}

export function buildXlsx(rows) {
  const shared = [];
  const indexOf = (v) => {
    const i = shared.indexOf(v);
    if (i >= 0) return i;
    shared.push(v);
    return shared.length - 1;
  };
  const sheetRows = rows
    .map((row, r) => {
      const cells = row
        .map((cell, c) => {
          const ref = `${colName(c)}${r + 1}`;
          if (typeof cell === 'number') return `<c r="${ref}"><v>${cell}</v></c>`;
          return `<c r="${ref}" t="s"><v>${indexOf(String(cell))}</v></c>`;
        })
        .join('');
      return `<row r="${r + 1}">${cells}</row>`;
    })
    .join('');
  const sheet = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>${sheetRows}</sheetData></worksheet>`;
  const sharedXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="${shared.length}" uniqueCount="${shared.length}">${shared
    .map((s) => `<si><t xml:space="preserve">${escapeXml(s)}</t></si>`)
    .join('')}</sst>`;
  const workbook = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Feuil1" sheetId="1" r:id="rId1"/></sheets></workbook>`;
  const contentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>
</Types>`;
  const rels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`;
  const wbRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rIdS1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
<Relationship Id="rIdSS" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>
</Relationships>`;
  return zip([
    ['[Content_Types].xml', contentTypes],
    ['_rels/.rels', rels],
    ['xl/workbook.xml', workbook],
    ['xl/_rels/workbook.xml.rels', wbRels],
    ['xl/worksheets/sheet1.xml', sheet],
    ['xl/sharedStrings.xml', sharedXml],
  ]);
}

/** Minimal uncompressed (STORE) zip writer — enough for OOXML fixtures. */
export function zip(entries) {
  const chunks = [];
  const central = [];
  let offset = 0;
  for (const [name, content] of entries) {
    const nameBuf = Buffer.from(name, 'utf8');
    const data = Buffer.from(content, 'utf8');
    const crc = crc32(data);
    const local = Buffer.alloc(30 + nameBuf.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(0, 8); // store
    local.writeUInt16LE(0, 10);
    local.writeUInt16LE(0, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28);
    nameBuf.copy(local, 30);
    chunks.push(local, data);

    const cd = Buffer.alloc(46 + nameBuf.length);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(20, 4); // version made by
    cd.writeUInt16LE(20, 6); // version needed
    cd.writeUInt16LE(0, 8); // flags
    cd.writeUInt16LE(0, 10); // method: store
    cd.writeUInt16LE(0, 12); // mod time
    cd.writeUInt16LE(0, 14); // mod date
    cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(data.length, 20);
    cd.writeUInt32LE(data.length, 24);
    cd.writeUInt16LE(nameBuf.length, 28);
    cd.writeUInt16LE(0, 30); // extra len
    cd.writeUInt16LE(0, 32); // comment len
    cd.writeUInt16LE(0, 34); // disk number
    cd.writeUInt16LE(0, 36); // internal attrs
    cd.writeUInt32LE(0, 38); // external attrs
    cd.writeUInt32LE(offset, 42); // local header offset
    nameBuf.copy(cd, 46);
    central.push(cd);
    offset += local.length + data.length;
  }
  const centralBuf = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);
  return Buffer.concat([...chunks, centralBuf, eocd]);
}

let CRC_TABLE = null;
function crc32(buf) {
  if (!CRC_TABLE) {
    CRC_TABLE = new Uint32Array(256);
    for (let n = 0; n < 256; n += 1) {
      let c = n;
      for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      CRC_TABLE[n] = c >>> 0;
    }
  }
  let crc = 0xffffffff;
  for (const byte of buf) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function colName(i) {
  let s = '';
  let n = i + 1;
  while (n > 0) {
    const m = (n - 1) % 26;
    s = String.fromCharCode(65 + m) + s;
    n = Math.floor((n - m - 1) / 26);
  }
  return s;
}

function escapeXml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/** A tiny, structurally valid PDF with one text stream (uncompressed). */
export function buildPdf(text = 'Rapport PrinceNsamba — ligne 1.\nBilan de securite.') {
  const safe = text.replace(/[()\\]/g, '');
  const content = `BT /F1 12 Tf 50 750 Td (${safe.replace(/\n/g, ') Tj T* (')}) Tj ET`;
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
    `<< /Length ${content.length} >>\nstream\n${content}\nendstream`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ];
  let out = '%PDF-1.4\n';
  const offsets = [];
  objects.forEach((body, i) => {
    offsets.push(Buffer.byteLength(out, 'latin1'));
    out += `${i + 1} 0 obj\n${body}\nendobj\n`;
  });
  const xrefStart = Buffer.byteLength(out, 'latin1');
  out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const off of offsets) out += `${String(off).padStart(10, '0')} 00000 n \n`;
  out += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF\n`;
  return Buffer.from(out, 'latin1');
}

export const PNG_1x1 = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFAAH/q842iQAAAABJRU5ErkJggg==',
  'base64',
);

export function multipart(fieldName, { filename, contentType, buffer, fields = {} }) {
  const boundary = `----psai${Math.random().toString(36).slice(2)}`;
  const head = [];
  for (const [k, v] of Object.entries(fields)) {
    head.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`, 'utf8'));
  }
  const fileHead = Buffer.from(
    `--${boundary}\r\nContent-Disposition: form-data; name="${fieldName}"; filename="${filename}"\r\nContent-Type: ${contentType}\r\n\r\n`,
    'utf8',
  );
  const tail = Buffer.from(`\r\n--${boundary}--\r\n`, 'utf8');
  return {
    headers: { 'content-type': `multipart/form-data; boundary=${boundary}` },
    body: Buffer.concat([...head, fileHead, buffer, tail]),
  };
}

/* ------------------------------------------------------------------ vidéo */
// Les fabricants ci-dessous produisent de VRAIS en-têtes de conteneurs (tailles
// de boîtes cohérentes, champs conformes aux structures publiées) : le sondeur
// est ainsi testé sur des fichiers que `ffprobe` lirait aussi, pas sur des
// approximations.

const be32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0, 0); return b; };
const le32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0, 0); return b; };
const le16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n & 0xffff, 0); return b; };
const uintBe = (n, bytes = 4) => {
  const b = Buffer.alloc(bytes);
  let v = Number(BigInt.asUintN(bytes * 8, BigInt(n)));
  for (let i = bytes - 1; i >= 0; i -= 1) { b[i] = v & 0xff; v = Math.floor(v / 256); }
  return b;
};
const ascii = (s, len = s.length) => Buffer.concat([Buffer.from(s, 'latin1'), Buffer.alloc(Math.max(0, len - s.length), 0)]).subarray(0, len);
const MATRIX33 = Buffer.concat([be32(0x00010000), be32(0), be32(0), be32(0), be32(0x00010000), be32(0), be32(0), be32(0), be32(0x40000000)]);

/** Boîte ISO BMFF : taille déclarée en grand boutien, puis type. */
function mp4Box(type, payload) {
  return Buffer.concat([be32(8 + payload.length), Buffer.from(type, 'latin1'), payload]);
}

/** En-tête d'images MP4/MOV minimal mais conforme (faststart : moov avant mdat). */
export function buildMp4({
  brand = 'isom',
  timescale = 1000,
  durationMs = 4000,
  width = 1280,
  height = 720,
  codec = 'avc1',
  mediaTimescale = 25,
  sampleDelta = 1,
  handler = 'vide',
  mdatSize = 2048,
  tailMode = false,
} = {}) {
  const ftyp = Buffer.concat([ascii(brand, 4), be32(0x200), ascii('isomiso2avc1mp41', 20)]);
  const mvhd = Buffer.concat([
    Buffer.alloc(4), be32(0), be32(0), be32(timescale), be32(Math.round((durationMs * timescale) / 1000)),
    be32(0x00010000), be16(0x0100), Buffer.alloc(2), MATRIX33, Buffer.alloc(24), be32(2),
  ]);
  const tkhd = Buffer.concat([
    Buffer.from([0, 0, 0, 7]), be32(0), be32(0), be32(1), be32(0), be32(Math.round((durationMs * timescale) / 1000)),
    Buffer.alloc(8), be16(0), be16(0), be16(0x0100), be16(0), MATRIX33, be32(width * 65536), be32(height * 65536),
  ]);
  const mdhd = Buffer.concat([Buffer.alloc(4), be32(0), be32(0), be32(mediaTimescale), be32(durationMs * mediaTimescale / 1000), be32(0)]);
    const hdlr = Buffer.concat([Buffer.alloc(4), be32(0), ascii(handler, 4), Buffer.alloc(12), ascii(`${handler} handler`, 16)]);
  const stsdEntry = Buffer.concat([be32(8 + 8 + 4 + 16 + 4), ascii(codec, 4), Buffer.alloc(6), be32(1), Buffer.alloc(16), be32(0)]);
  const stsd = Buffer.concat([Buffer.alloc(4), be32(1), stsdEntry]);
  const stts = Buffer.concat([Buffer.alloc(4), be32(1), be32(Math.round((durationMs / 1000) * mediaTimescale / sampleDelta)), be32(sampleDelta)]);
  const stbl = mp4Box('stbl', Buffer.concat([mp4Box('stsd', stsd), mp4Box('stts', stts)]));
  const minf = mp4Box('minf', stbl);
  const mdia = mp4Box('mdia', Buffer.concat([mp4Box('mdhd', mdhd), mp4Box('hdlr', hdlr), minf]));
  const trak = mp4Box('trak', Buffer.concat([mp4Box('tkhd', tkhd), mdia]));
  const moov = mp4Box('moov', Buffer.concat([mp4Box('mvhd', mvhd), trak]));
  const mdat = mp4Box('mdat', Buffer.alloc(mdatSize, 0x21));
  const head = Buffer.concat([mp4Box('ftyp', ftyp), tailMode ? mdat : moov]);
  return tailMode ? Buffer.concat([head, moov]) : Buffer.concat([head, mdat]);
}

function be16(v) { const b = Buffer.alloc(2); b.writeUInt16BE(v & 0xffff, 0); return b; }

/** En-tête EBML de taille variable (bit de marque inclus dans l'identifiant). */
function ebmlElement(idBytes, payload) {
  const len = payload.length;
  let size;
  if (len < 0x7f) size = Buffer.from([0x80 | len]);
  else if (len < 0x3fff) size = Buffer.from([0x40 | (len >> 8), len & 0xff]);
  else if (len < 0x1fffff) size = Buffer.from([0x20 | (len >> 16), (len >> 8) & 0xff, len & 0xff]);
  else size = Buffer.from([0x10 | (len >> 24), (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff]);
  return Buffer.concat([idBytes, size, payload]);
}

const ID = {
  ebml: Buffer.from([0x1a, 0x45, 0xdf, 0xa3]),
  doctype: Buffer.from([0x42, 0x82]),
  doctypeVersion: Buffer.from([0x42, 0x87]),
  version: Buffer.from([0x42, 0x86]),
  segment: Buffer.from([0x18, 0x53, 0x80, 0x67]),
  info: Buffer.from([0x15, 0x49, 0xa9, 0x66]),
  timecodeScale: Buffer.from([0x2a, 0xd7, 0xb1]),
  duration: Buffer.from([0x44, 0x89]),
  tracks: Buffer.from([0x16, 0x54, 0xae, 0x6b]),
  track: Buffer.from([0xae]),
  trackNumber: Buffer.from([0xd7]),
  trackType: Buffer.from([0x83]),
  codecId: Buffer.from([0x86]),
  defaultDuration: Buffer.from([0x23, 0x83, 0xe8]),
  video: Buffer.from([0xe0]),
  audio: Buffer.from([0xe1]),
  pixelWidth: Buffer.from([0xb0]),
  pixelHeight: Buffer.from([0xba]),
  cluster: Buffer.from([0x1f, 0x43, 0xb6, 0x75]),
};

/** WebM/Matroska minimal : en-tête EBML + Info + deux pistes + une grappe. */
export function buildWebm({ doctype = 'webm', timecodeScale = 1_000_000, durationMs = 3200, width = 640, height = 360, videoCodec = 'V_VP8', audioCodec = 'A_VORBIS', fps = 25 } = {}) {
  const header = ebmlElement(ID.ebml, Buffer.concat([
    ebmlElement(ID.version, uintBe(1, 1)),
    ebmlElement(ID.doctype, Buffer.from(doctype, 'latin1')),
    ebmlElement(ID.doctypeVersion, uintBe(4, 1)),
  ]));
  const info = ebmlElement(ID.info, Buffer.concat([
    ebmlElement(ID.timecodeScale, uintBe(timecodeScale, 4)),
    ebmlElement(ID.duration, float64Be((durationMs * 1_000_000) / timecodeScale)),
  ]));
  const videoTrack = ebmlElement(ID.track, Buffer.concat([
    ebmlElement(ID.trackNumber, uintBe(1, 1)),
    ebmlElement(ID.trackType, uintBe(1, 1)),
    ebmlElement(ID.codecId, Buffer.from(videoCodec, 'latin1')),
    ebmlElement(ID.defaultDuration, uintBe(Math.round(1_000_000_000 / fps), 8)),
    ebmlElement(ID.video, Buffer.concat([ebmlElement(ID.pixelWidth, uintBe(width, 2)), ebmlElement(ID.pixelHeight, uintBe(height, 2))])),
  ]));
  const audioTrack = ebmlElement(ID.track, Buffer.concat([
    ebmlElement(ID.trackNumber, uintBe(2, 1)),
    ebmlElement(ID.trackType, uintBe(2, 1)),
    ebmlElement(ID.codecId, Buffer.from(audioCodec, 'latin1')),
    ebmlElement(ID.audio, Buffer.alloc(0)),
  ]));
  const tracks = ebmlElement(ID.tracks, Buffer.concat([videoTrack, audioTrack]));
  const cluster = ebmlElement(ID.cluster, Buffer.alloc(24, 0x5a));
  return Buffer.concat([header, ebmlElement(ID.segment, Buffer.concat([info, tracks, cluster]))]);
}

function float64Be(v) { const b = Buffer.alloc(8); b.writeDoubleBE(v, 0); return b; }

/** AVI (RIFF) : en-tête principal + une piste vidéo + BITMAPINFOHEADER + index. */
export function buildAvi({ microSecPerFrame = 40_000, frames = 100, width = 640, height = 480, codec = 'DIVX', entries = 2 } = {}) {
  const avih = Buffer.concat([
    le32(microSecPerFrame), le32(0), le32(0), le32(0x10), le32(1), le32(0), le32(0), le32(0),
    le32(width), le32(height), Buffer.alloc(16),
  ]);
  // AVISTREAMHEADER : fccType 0, fccHandler 4, dwFlags 8, prio/lang 12,
  // dwInitialFrames 16, dwScale 20, dwRate 24, dwStart 28, dwLength 32,
  // dwSuggestedBufferSize 36, dwPreroll 40, dwQuality 44, dwSampleSize 48, rcFrame 52.
  const strh = Buffer.concat([
    ascii('vids', 4),
    ascii(codec, 4),
    le32(0), // dwFlags
    le32(0), // wPriority + wLanguage
    le32(0), // dwInitialFrames
    le32(1), // dwScale
    le32(Math.round(1_000_000 / microSecPerFrame)), // dwRate  (25 images/seconde avec 40 000 µs)
    le32(0), // dwStart
    le32(frames), // dwLength
    le32(0), // dwSuggestedBufferSize
    le32(0), // dwPreroll
    le32(0xffffffff), // dwQuality
    le32(0), // dwSampleSize
    Buffer.alloc(16), // rcFrame
  ]);
  const strf = Buffer.concat([
    le32(40), le32(width), le32(height), le16(1), le16(24), ascii(codec, 4), le32(width * height * 3), le32(0), le32(0), le32(0), le32(0),
  ]);
  const strl = LIST('strl', Buffer.concat([chunk('strh', strh), chunk('strf', strf)]));
  const hdrl = LIST('hdrl', Buffer.concat([chunk('avih', avih), strl]));
  const idx1 = Buffer.concat(Array.from({ length: entries }, () => Buffer.concat([ascii('00db', 4), le32(0x10), le32(64), le32(1)])));
  const movi = LIST('movi', chunk('00db', Buffer.alloc(64, 0x33)));
  const body = Buffer.concat([hdrl, movi, chunk('idx1', idx1)]);
  return Buffer.concat([ascii('RIFF', 4), le32(4 + body.length), ascii('AVI ', 4), body]);
}

function chunk(id, payload) {
  const pad = payload.length % 2;
  return Buffer.concat([ascii(id, 4), le32(payload.length), payload, Buffer.alloc(pad)]);
}
function LIST(kind, inner) {
  return Buffer.concat([ascii('LIST', 4), le32(inner.length + 4), ascii(kind, 4), inner]);
}
