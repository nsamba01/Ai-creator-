/**
 * Document analysis service (the "Agent documentaire").
 *
 * Supported: TXT, MD, LOG, YAML, JSON, CSV/TSV, DOCX, XLSX, PDF (best effort),
 * and images (structural metadata only — no OCR here, see docs/ARCHITECTURE.md).
 *
 * Implementation notes:
 *  - pure JS, no third-party parser => no supply-chain surface for hostile
 *    documents;
 *  - every parser is bounded (bytes, rows, entries) and never writes to disk;
 *  - XML-ish content is read with explicit regex extraction, not a permissive
 *    DOM parser, so entity expansion (XXE) has no interpreter to exploit.
 */
import zlib from 'node:zlib';
import { readZip, ZipError } from './zip.js';
import { badRequest, AppError } from '../utils/errors.js';

const MAX_ROWS = 5000;
const MAX_COLS = 300;
const MAX_TEXT = 200_000;

/* ------------------------------------------------------------------ helpers */

export function utf8(buf) {
  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(buf).replace(/^\uFEFF/, '');
  } catch {
    return '';
  }
}

function wordCount(text) {
  const m = String(text).match(/[^\s]+/g);
  return m ? m.length : 0;
}

function charCount(text) {
  return Array.from(String(text)).length;
}

const SECRET_PATTERNS = [
  { name: 'clé AWS', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'clé privée', re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g },
  { name: 'jeton GitHub', re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g },
  { name: 'jeton Slack', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { name: 'JWT', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { name: 'mot de passe en clair', re: /\b(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*["']?(?!\$\{|\{\{|REDACTED)[^\s"',;]{6,}/gi },
  { name: 'hachage PHC', re: /\$(?:argon2id|argon2i|2[aby])\$\d{1,3}\$[A-Za-z0-9./]{10,}/g },
  { name: 'URL avec identifiants', re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s/@:]+:[^\s/@]+@/gi },
];

const PII_PATTERNS = [
  { name: 'adresse e-mail', re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g },
  { name: 'téléphone (format FR)', re: /\b(?:\+33|0)[1-9](?:[\s.-]?\d{2}){4}\b/g },
  { name: 'SIRET', re: /\b\d{3} \d{3} \d{3} \d{5}\b|\b\d{14}\b/g },
  { name: 'IBAN', re: /\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/g },
];

function scanPatterns(text, patterns) {
  const hits = [];
  for (const { name, re } of patterns) {
    const matches = String(text).match(re);
    if (matches && matches.length) hits.push({ name, count: matches.length });
  }
  return hits;
}

/** Counts are reported, values never. */
function redactHits(hits) {
  return hits.map((h) => ({ type: h.name, occurrences: h.count }));
}

/* --------------------------------------------------------------------- text */

export function analyzeText(buffer, ext) {
  const text = utf8(buffer);
  const findings = [];
  const lines = text.split(/\r\n|\r|\n/);
  const metrics = {
    characters: charCount(text),
    words: wordCount(text),
    lines: lines.length,
    nonEmptyLines: lines.filter((l) => l.trim()).length,
    bytes: buffer.length,
    longestLine: lines.reduce((m, l) => Math.max(m, l.length), 0),
  };
  if (metrics.longestLine > 500) findings.push({ level: 'info', message: `Ligne très longue détectée (${metrics.longestLine} caractères).` });
  if (/(TODO|FIXME|XXX|HACK)[:\s]/.test(text)) findings.push({ level: 'info', message: 'Marqueurs TODO/FIXME présents.' });
  if (/\t/.test(text) && ext !== '.tsv') findings.push({ level: 'info', message: 'Tabulations présentes (fichier potentiellement tabulaire).' });
  if (buffer.includes(0)) findings.push({ level: 'warning', message: 'Octets nuls : le fichier semble binaire.' });
  const secrets = scanPatterns(text, SECRET_PATTERNS);
  if (secrets.length) findings.push({ level: 'critical', message: `Secrets potentiels détectés : ${secrets.map((s) => s.name).join(', ')}.`, values: redactHits(secrets) });
  const pii = scanPatterns(text, PII_PATTERNS);
  if (pii.length) findings.push({ level: 'warning', message: `Données personnelles probables : ${pii.map((s) => s.name).join(', ')}.`, values: redactHits(pii) });

  const textForSummary = text.slice(0, MAX_TEXT);
  return {
    status: 'ok',
    kind: 'text',
    text: textForSummary,
    metrics,
    findings,
    summary: buildSummary({ kind: 'texte', metrics, findings }),
  };
}

export function analyzeMarkdown(buffer) {
  const base = analyzeText(buffer, '.md');
  const text = base.text;
  const headings = [];
  const re = /^(#{1,6})\s+(.*)$/gm;
  let m;
  while ((m = re.exec(text)) && headings.length < 200) headings.push({ level: m[1].length, title: m[2].trim().slice(0, 120) });
  const links = (text.match(/\[[^\]]+\]\((https?:\/\/[^)\s]+)\)/g) ?? []).length;
  const fenceOpen = (text.match(/```/g) ?? []).length;
  const code = Math.floor(fenceOpen / 2);
  return {
    ...base,
    kind: 'markdown',
    metrics: { ...base.metrics, headings: headings.length, links, codeBlocks: code },
    structure: { headings: headings.slice(0, 60) },
    findings: [
      ...base.findings,
      ...(fenceOpen % 2 ? [{ level: 'warning', message: 'Bloc de code non fermé.' }] : []),
      ...(headings.length === 0 ? [{ level: 'info', message: 'Aucun titre Markdown : hiérarchie du document absente.' }] : []),
    ],
    summary: buildSummary({ kind: 'Markdown', metrics: { ...base.metrics, headings: headings.length }, findings: base.findings }),
  };
}

/* --------------------------------------------------------------------- json */

export function analyzeJson(buffer) {
  const raw = utf8(buffer);
  let value;
  try {
    value = JSON.parse(raw);
  } catch (err) {
    return {
      status: 'failed',
      kind: 'json',
      text: raw.slice(0, MAX_TEXT),
      metrics: { bytes: buffer.length },
      findings: [{ level: 'critical', message: `JSON invalide : ${String(err.message).slice(0, 160)}` }],
      summary: 'JSON invalide : le document n’a pas pu être analysé.',
    };
  }
  const stats = { nodes: 0, maxDepth: 0, arrays: 0, objects: 0, strings: 0, numbers: 0, booleans: 0, nulls: 0, keys: new Set() };
  const typeCounts = {};
  (function walk(node, depth) {
    stats.nodes += 1;
    stats.maxDepth = Math.max(stats.maxDepth, depth);
    if (Array.isArray(node)) {
      stats.arrays += 1;
      typeCounts.array = (typeCounts.array ?? 0) + 1;
      for (const item of node.slice(0, 5000)) walk(item, depth + 1);
      return;
    }
    if (node && typeof node === 'object') {
      stats.objects += 1;
      typeCounts.object = (typeCounts.object ?? 0) + 1;
      for (const [k, v] of Object.entries(node)) {
        stats.keys.add(k);
        walk(v, depth + 1);
      }
      return;
    }
    const t = node === null ? 'null' : typeof node;
    typeCounts[t] = (typeCounts[t] ?? 0) + 1;
    if (t === 'string') stats.strings += 1;
    else if (t === 'number') stats.numbers += 1;
    else if (t === 'boolean') stats.booleans += 1;
    else if (t === 'null') stats.nulls += 1;
  })(value, 1);

  const findings = [];
  if (stats.maxDepth > 20) findings.push({ level: 'warning', message: `Imbrication profonde (${stats.maxDepth} niveaux).` });
  if (stats.nodes > 50000) findings.push({ level: 'info', message: `Document volumineux (${stats.nodes} nœuds).` });
  // Detecte aussi les cles francaises : un document de l'outil est rarement en anglais.
  if (/"(?:password|passwd|pwd|mot[ _-]?de[ _-]?passe|token|secret|api[ _-]?key|cle[ _-]?api|cle|auth[ _-]?token|refresh[ _-]?token|prive[ _-]?key)"\s*:/i.test(raw)) {
    findings.push({ level: 'critical', message: 'Champs sensibles présents dans le JSON (valeurs non affichées).' });
  }
  const top = Array.isArray(value)
    ? { shape: 'array', length: value.length }
    : value && typeof value === 'object'
      ? { shape: 'object', keys: Object.keys(value).slice(0, 40) }
      : { shape: typeof value, value: typeof value === 'object' ? null : value };

  const metrics = {
    bytes: buffer.length,
    nodes: stats.nodes,
    maxDepth: stats.maxDepth,
    uniqueKeys: stats.keys.size,
    typeCounts,
  };
  return {
    status: 'ok',
    kind: 'json',
    text: raw.slice(0, 20000),
    metrics,
    structure: top,
    findings,
    summary: buildSummary({ kind: 'JSON', metrics, findings, extra: `forme ${top.shape}` }),
  };
}

/* ---------------------------------------------------------------------- csv */

export function detectDelimiter(sample) {
  const firstLine = sample.split(/\r?\n/)[0] ?? '';
  const counts = [
    { d: ',', n: (firstLine.match(/,/g) ?? []).length },
    { d: ';', n: (firstLine.match(/;/g) ?? []).length },
    { d: '\t', n: (firstLine.match(/\t/g) ?? []).length },
    { d: '|', n: (firstLine.match(/\|/g) ?? []).length },
  ].sort((a, b) => b.n - a.n);
  return counts[0].n > 0 ? counts[0].d : ',';
}

/** RFC4180-ish parser with quotes, escaped quotes and embedded newlines. */
export function parseDelimited(text, delimiter = ',') {
  const rows = [];
  let field = '';
  let row = [];
  let inQuotes = false;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 1;
        } else inQuotes = false;
      } else field += c;
      continue;
    }
    if (c === '"') {
      inQuotes = true;
      continue;
    }
    if (c === delimiter) {
      row.push(field);
      field = '';
      continue;
    }
    if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i += 1;
      row.push(field);
      field = '';
      if (row.length > 1 || row[0] !== '') rows.push(row);
      if (rows.length >= MAX_ROWS + 2) break;
      row = [];
      continue;
    }
    field += c;
  }
  if (field !== '' || row.length) {
    row.push(field);
    if (row.length > 1 || row[0] !== '') rows.push(row);
  }
  return rows;
}

export function analyzeCsv(buffer, { delimiter } = {}) {
  const text = utf8(buffer);
  const delim = delimiter ?? detectDelimiter(text);
  const rows = parseDelimited(text, delim);
  const findings = [];
  if (!rows.length) {
    return { status: 'failed', kind: 'csv', text: '', metrics: {}, findings: [{ level: 'warning', message: 'Aucune ligne exploitable.' }], summary: 'Fichier CSV vide.' };
  }
  const header = rows[0].map((h, i) => String(h).trim() || `colonne_${i + 1}`);
  const body = rows.slice(1);
  const columns = header.map((name, idx) => ({
    name,
    index: idx,
    filled: 0,
    missing: 0,
    numeric: 0,
    integer: 0,
    dateLike: 0,
    emptyStrings: 0,
    blanks: 0,
    min: null,
    max: null,
    sum: 0,
    distinct: new Set(),
    samples: [],
  }));

  let raggedRows = 0;
  let duplicateRowHashes = 0;
  const seenRows = new Set();
  for (const r of body) {
    if (r.length !== header.length) raggedRows += 1;
    const key = r.join(delim);
    if (seenRows.has(key)) duplicateRowHashes += 1;
    else if (seenRows.size < 20000) seenRows.add(key);
    for (let c = 0; c < header.length; c += 1) {
      const col = columns[c];
      const raw = r[c];
      if (raw === undefined || raw.trim() === '') {
        col.missing += 1;
        if (raw === '') col.emptyStrings += 1;
        col.blanks += 1;
        continue;
      }
      col.filled += 1;
      if (col.distinct.size < 5000) col.distinct.add(raw);
      if (col.samples.length < 3) col.samples.push(String(raw).slice(0, 40));
      const trimmed = raw.trim();
      if (/^[+-]?\d{1,3}(?:[ .]\d{3})*(?:[.,]\d+)?$/.test(trimmed)) {
        col.numeric += 1;
        if (/^[+-]?\d{1,3}(?:[ .]\d{3})*$/.test(trimmed)) col.integer += 1;
        const n = Number(trimmed.replace(/[ .]/g, '').replace(',', '.'));
        if (Number.isFinite(n)) {
          col.min = col.min === null ? n : Math.min(col.min, n);
          col.max = col.max === null ? n : Math.max(col.max, n);
          col.sum += n;
        }
      } else if (/^\d{4}-\d{2}-\d{2}([T ].*)?$/.test(trimmed) || /^\d{1,2}[/-]\d{1,2}[/-]\d{2,4}$/.test(trimmed)) {
        col.dateLike += 1;
      }
    }
  }

  const total = body.length;
  const colReport = columns.map((c) => ({
    name: c.name,
    filled: c.filled,
    missing: c.missing,
    missingRate: total ? Math.round((c.missing / total) * 1000) / 10 : 0,
    distinct: c.distinct.size,
    inferredType: c.numeric > total * 0.6 && total > 0 ? (c.integer > total * 0.6 ? 'integer' : 'number') : c.dateLike > total * 0.6 && total > 0 ? 'date' : 'string',
    min: c.min === null ? undefined : Math.round(c.min * 1000) / 1000,
    max: c.max === null ? undefined : Math.round(c.max * 1000) / 1000,
    samples: c.samples,
  }));

  const dupHeader = header.filter((h, i) => header.indexOf(h) !== i);
  if (dupHeader.length) findings.push({ level: 'warning', message: `En-têtes dupliqués : ${[...new Set(dupHeader)].join(', ')}.` });
  if (raggedRows) findings.push({ level: 'warning', message: `${raggedRows} ligne(s) avec un nombre de colonnes différent de l’en-tête.` });
  if (duplicateRowHashes) findings.push({ level: 'info', message: `${duplicateRowHashes} ligne(s) exactement dupliquée(s).` });
  for (const c of colReport) {
    if (c.missingRate >= 50) findings.push({ level: 'warning', message: `Colonne « ${c.name} » manquante à ${c.missingRate} %.` });
  }
  const csvSample = body.slice(0, 200).map((r) => r.join(delim)).join('\n');
  const secrets = scanPatterns(csvSample, SECRET_PATTERNS);
  if (secrets.length) findings.push({ level: 'critical', message: 'Secrets potentiels dans les 200 premières lignes.', values: redactHits(secrets) });
  const pii = scanPatterns(csvSample, PII_PATTERNS);
  if (pii.length) findings.push({ level: 'warning', message: 'Données personnelles probables (échantillon).', values: redactHits(pii) });

  const metrics = {
    delimiter: delim === '\t' ? 'TAB' : delim,
    rows: total,
    columns: header.length,
    raggedRows,
    duplicateRows: duplicateRowHashes,
    cells: total * header.length,
    missingCells: colReport.reduce((s, c) => s + c.missing, 0),
  };
  return {
    status: total ? 'ok' : 'partial',
    kind: 'csv',
    text: `${header.join(delim)}\n${body.slice(0, 50).map((r) => r.join(delim)).join('\n')}`.slice(0, MAX_TEXT),
    metrics,
    structure: { header, columns: colReport, preview: body.slice(0, 10).map((r) => r.slice(0, 12)) },
    findings,
    summary: buildSummary({ kind: `tableau CSV (${metrics.rows} lignes × ${metrics.columns} colonnes)`, metrics, findings }),
  };
}

/* --------------------------------------------------------------------- xlsx */

function decodeXmlEntities(s) {
  return String(s)
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => safeCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => safeCodePoint(parseInt(d, 10)))
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&');
}

function safeCodePoint(n) {
  try {
    return Number.isFinite(n) && n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : '';
  } catch {
    return '';
  }
}

function colLetterToIndex(ref) {
  const m = /([A-Z]{1,3})\d+/.exec(String(ref).toUpperCase());
  if (!m) return 0;
  let n = 0;
  for (const ch of m[1]) n = n * 26 + (ch.charCodeAt(0) - 64);
  return Math.min(n - 1, MAX_COLS - 1);
}

export function analyzeXlsx(buffer) {
  let zip;
  try {
    zip = readZip(buffer);
  } catch (err) {
    throw new AppError(415, 'CORRUPT_ARCHIVE', `Classeur illisible : ${err instanceof ZipError ? err.message : 'archive invalide'}.`);
  }
  const shared = [];
  const sharedXml = zip.get('xl/sharedStrings.xml');
  if (sharedXml) {
    const text = utf8(sharedXml);
    const siRe = /<si>([\s\S]*?)<\/si>/g;
    let m;
    while ((m = siRe.exec(text)) && shared.length < 100000) {
      const parts = [...m[1].matchAll(/<t[^>]*>([\s\S]*?)<\/t>/g)].map((p) => decodeXmlEntities(p[1]));
      shared.push(parts.join(''));
    }
  }

  const sheetNames = [];
  const wb = zip.get('xl/workbook.xml');
  if (wb) {
    for (const m of utf8(wb).matchAll(/<sheet[^>]*name="([^"]*)"[^>]*\/?>/g)) sheetNames.push(decodeXmlEntities(m[1]));
  }
  const sheetFiles = zip.names
    .filter((n) => /^xl\/worksheets\/sheet\d+\.xml$/.test(n))
    .sort((a, b) => Number(a.replace(/\D/g, '')) - Number(b.replace(/\D/g, '')));
  if (!sheetFiles.length) throw new AppError(415, 'CORRUPT_ARCHIVE', 'Aucune feuille trouvée dans le classeur.');

  const sheets = [];
  for (let i = 0; i < sheetFiles.length && i < 10; i += 1) {
    const xml = utf8(zip.get(sheetFiles[i]));
    const rows = [];
    const rowRe = /<row[^>]*r="(\d+)"[^>]*>([\s\S]*?)<\/row>/g;
    let rm;
    while ((rm = rowRe.exec(xml)) && rows.length < MAX_ROWS) {
      const cells = [];
      const cellRe = /<c([^>]*)>([\s\S]*?)<\/c>|<c([^>]*)\/>/g;
      let cm;
      const inner = rm[2] ?? '';
      while ((cm = cellRe.exec(inner)) && cells.length < MAX_COLS) {
        const attrs = cm[1] ?? cm[3] ?? '';
        const body = cm[2] ?? '';
        const tMatch = /t="([^"]+)"/.exec(attrs);
        const type = tMatch ? tMatch[1] : 'n';
        const refMatch = /r="([A-Z]+\d+)"/.exec(attrs);
        const idx = refMatch ? colLetterToIndex(refMatch[1]) : cells.length;
        let value = '';
        if (type === 's') {
          const v = /<v>([\s\S]*?)<\/v>/.exec(body);
          value = v ? shared[Number(v[1])] ?? '' : '';
        } else if (type === 'inlineStr') {
          value = [...body.matchAll(/<t[^>]*>([\s\S]*?)<\/t>/g)].map((p) => decodeXmlEntities(p[1])).join('');
        } else {
          const v = /<v>([\s\S]*?)<\/v>/.exec(body);
          const raw = v ? decodeXmlEntities(v[1]) : '';
          // Une cellule sans attribut t est numérique au sens OOXML : on la rend
          // typée (sinon « 10 » + « 20 » se concatène côté client).
          if (type === 'n' && /^-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?$/.test(raw)) value = Number(raw);
          else if (type === 'b') value = raw === '1';
          else value = raw;
        }
        cells[idx === undefined ? cells.length : Math.min(idx, MAX_COLS - 1)] = value;
      }
      rows.push(rows.length ? fillRow(cells) : fillRow(cells));
    }
    const numericCols = {};
    for (const r of rows.slice(0, 500)) {
      for (let c = 0; c < r.length; c += 1) {
        if (r[c] !== undefined && r[c] !== '' && /^-?\d+(?:\.\d+)?$/.test(String(r[c]))) numericCols[c] = (numericCols[c] ?? 0) + 1;
      }
    }
    sheets.push({
      name: sheetNames[i] ?? `Sheet${i + 1}`,
      rows: rows.length,
      columns: rows.reduce((m, r) => Math.max(m, r.length), 0),
      numericColumns: Object.keys(numericCols).length,
      preview: rows.slice(0, 10).map((r) => r.slice(0, 12).map((x) => (x === undefined ? '' : String(x)))),
      hasFormulas: /<f[ >]/.test(xml),
      hasPivotCache: zip.names.some((n) => n.startsWith('xl/pivotCache/')),
      hasMacros: zip.names.some((n) => n.endsWith('vbaProject.bin')),
    });
  }

  const first = sheets[0];
  const findings = [];
  if (sheets.some((s) => s.hasMacros)) findings.push({ level: 'critical', message: 'Le classeur contient un projet VBA (macros) : risque d’exécution.' });
  if (first && first.rows === 0) findings.push({ level: 'warning', message: 'Première feuille vide.' });
  const metadata = zip.has('docProps/core.xml') ? extractDocProps(utf8(zip.get('docProps/core.xml'))) : {};
  if (metadata.creator) findings.push({ level: 'info', message: `Auteur déclaré du classeur : ${metadata.creator}.` });

  const metrics = { sheets: sheets.length, totalRows: sheets.reduce((s, x) => s + x.rows, 0), maxColumns: Math.max(0, ...sheets.map((s) => s.columns)) };
  return {
    status: 'ok',
    kind: 'xlsx',
    text: sheets.map((s) => `# ${s.name}\n${s.preview.map((r) => r.join(' | ')).join('\n')}`).join('\n\n').slice(0, MAX_TEXT),
    metrics: { ...metrics, bytes: buffer.length, core: metadata },
    structure: { sheets },
    findings,
    summary: buildSummary({ kind: 'classeur XLSX', metrics, findings, extra: `${sheets.length} feuille(s)` }),
  };
}

function fillRow(cells) {
  const out = [];
  const max = Math.min(cells.length, MAX_COLS);
  for (let i = 0; i < max; i += 1) out.push(cells[i] === undefined ? '' : cells[i]);
  return out;
}

function extractDocProps(xml) {
  const get = (tag) => {
    const m = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`).exec(xml);
    return m ? decodeXmlEntities(m[1]).trim() : undefined;
  };
  return { creator: get('dc:creator'), lastModifiedBy: get('cp:lastModifiedBy'), title: get('dc:title'), created: get('dcterms:created'), modified: get('dcterms:modified') };
}

/* --------------------------------------------------------------------- docx */

export function analyzeDocx(buffer) {
  let zip;
  try {
    zip = readZip(buffer);
  } catch (err) {
    throw new AppError(415, 'CORRUPT_ARCHIVE', `Document Word illisible : ${err instanceof ZipError ? err.message : 'archive invalide'}.`);
  }
  const main = zip.get('word/document.xml');
  if (!main) throw new AppError(415, 'CORRUPT_ARCHIVE', 'Document Word sans corps (word/document.xml absent).');
  const xml = utf8(main);

  const paragraphs = [];
  const headings = [];
  const pRe = /<w:p[ >][\s\S]*?<\/w:p>|<w:p\/>/g;
  let pm;
  while ((pm = pRe.exec(xml)) && paragraphs.length < 20000) {
    const chunk = pm[0];
    const text = [...chunk.matchAll(/<w:t[^>]*>([\s\S]*?)<\/w:t>/g)].map((m) => decodeXmlEntities(m[1])).join('');
    const style = /<w:pStyle w:val="([^"]+)"/.exec(chunk)?.[1] ?? '';
    if (!text.trim() && !style) continue;
    paragraphs.push({ text: text.trim(), style });
    if (/^(\d|[Hh]eading[1-9]|Titre[1-9]|Heading[1-9])$/.test(style) || /heading|titre/i.test(style)) {
      const level = Number.parseInt(style.replace(/\D/g, ''), 10) || 1;
      headings.push({ level, title: text.trim().slice(0, 160) });
    }
  }

  const tables = (xml.match(/<w:tbl[ >]/g) ?? []).length;
  const images = zip.names.filter((n) => n.startsWith('word/media/')).length;
  const hyperlinks = [...zip.get('word/_rels/document.xml.rels')?.toString('utf8')?.matchAll(/TargetMode="External"[^>]*Target="([^"]*)"/g), ...[...(zip.get('word/_rels/document.xml.rels') ?? Buffer.from('')).toString('utf8').matchAll(/Target="(https?:\/\/[^"]*)"/g)]].map((m) => m[1]);
  const comments = zip.has('word/comments.xml');
  const trackedChanges = /<w:(ins|del)[ >]/.test(xml);
  const fullText = paragraphs.map((p) => p.text).join('\n');
  const text = fullText.slice(0, MAX_TEXT);

  const findings = [];
  if (comments) findings.push({ level: 'notice', message: 'Commentaires présents : vérifier avant diffusion.' });
  if (trackedChanges) findings.push({ level: 'notice', message: 'Modifications suivies présentes dans le document.' });
  if (zip.has('docProps/custom.xml')) findings.push({ level: 'info', message: 'Propriétés personnalisées présentes.' });
  const externalLinks = hyperlinks.filter((u) => /^https?:\/\//i.test(String(u)));
  if (externalLinks.length) findings.push({ level: 'info', message: `${externalLinks.length} lien(s) externe(s) : ne pas cliquer sans vérification.` });
  if (!headings.length) findings.push({ level: 'info', message: 'Aucun titre de style repéré : plan du document peu structuré.' });
  const secrets = scanPatterns(text, SECRET_PATTERNS);
  if (secrets.length) findings.push({ level: 'critical', message: 'Contenu sensible détecté dans le texte.', values: redactHits(secrets) });
  const pii = scanPatterns(text, PII_PATTERNS);
  if (pii.length) findings.push({ level: 'warning', message: 'Données personnelles détectées dans le texte.', values: redactHits(pii) });
  const metadata = zip.has('docProps/core.xml') ? extractDocProps(utf8(zip.get('docProps/core.xml'))) : {};
  if (metadata.creator) findings.push({ level: 'info', message: `Auteur déclaré : ${metadata.creator}.` });

  const metrics = {
    paragraphs: paragraphs.length,
    words: wordCount(text),
    characters: charCount(text),
    headings: headings.length,
    tables,
    images,
    externalLinks: externalLinks.length,
    bytes: buffer.length,
  };
  return {
    status: 'ok',
    kind: 'docx',
    text,
    metrics,
    structure: { headings: headings.slice(0, 60), metadata, firstParagraphs: paragraphs.slice(0, 5).map((p) => p.text.slice(0, 240)) },
    findings,
    summary: buildSummary({ kind: 'document Word', metrics, findings, extra: `${headings.length} titre(s), ${tables} tableau(x)` }),
  };
}

/* ---------------------------------------------------------------------- pdf */

function inflateStreams(buffer) {
  const out = [];
  const re = /stream\r?\n?/g;
  let m;
  while ((m = re.exec(buffer.toString('latin1'))) !== null) {
    const start = m.index + m[0].length;
    const end = buffer.indexOf('endstream', start);
    if (end === -1) break;
    const chunk = buffer.subarray(start, end);
    try {
      out.push(zlib.inflateSync(chunk, { finishFlush: zlib.constants.ZLIB_SYNC_FLUSH }));
    } catch {
      try {
        out.push(zlib.inflateRawSync(chunk));
      } catch {
        out.push(chunk); // uncompressed stream
      }
    }
    re.lastIndex = end;
  }
  return out;
}

function unescapePdfString(s) {
  let out = '';
  for (let i = 0; i < s.length; i += 1) {
    const c = s[i];
    if (c !== '\\') {
      out += c;
      continue;
    }
    const n = s[i + 1];
    if (n === undefined) break;
    if ('nrtbf'.includes(n)) {
      out += { n: '\n', r: '\r', t: '\t', b: '\b', f: '\f' }[n];
      i += 1;
    } else if (n === '\n') {
      i += 1; // line continuation
    } else if (/[0-7]/.test(n)) {
      const oct = /^[0-7]{1,3}/.exec(s.slice(i + 1))[0];
      out += String.fromCharCode(parseInt(oct, 8));
      i += oct.length;
    } else {
      out += n;
      i += 1;
    }
  }
  return out;
}

function extractTextOperators(content) {
  const text = [];
  const s = content.toString('latin1');
  // (literal) Tj, [(..)..] TJ, ' and " operators
  const re = /\((?:\\.|[^\\()])*\)\s*(?:Tj|TJ|'|")|\[[\s\S]{0,4000}?\]\s*TJ|<[0-9A-Fa-f\s]+>\s*Tj/g;
  let m;
  while ((m = re.exec(s)) !== null) {
    const tok = m[0];
    if (tok.startsWith('[')) {
      const parts = [...tok.matchAll(/\((?:\\.|[^\\()])*\)|<[0-9A-Fa-f\s]+>/g)];
      for (const p of parts) {
        const v = p[0];
        if (v.startsWith('(')) text.push(unescapePdfString(v.slice(1, -1)));
        else text.push(Buffer.from(v.slice(1, -1).replace(/\s+/g, ''), 'hex').toString('latin1'));
      }
      text.push(' ');
    } else if (tok.startsWith('(')) {
      text.push(unescapePdfString(tok.slice(1, tok.lastIndexOf(')'))));
      if (/[Tt]j|'|"\s*$/.test(tok) === false) text.push('');
      text.push('');
    } else {
      text.push(Buffer.from(tok.slice(1, tok.lastIndexOf('>')).replace(/\s+/g, ''), 'hex').toString('latin1'));
    }
    if (text.join('').length > 400000) break;
  }
  return text.join('');
}

export function analyzePdf(buffer) {
  const head = buffer.subarray(0, 1024).toString('latin1');
  if (!head.startsWith('%PDF-')) throw new AppError(415, 'CORRUPT_PDF', 'En-tête PDF absent.');
  const raw = buffer.toString('latin1');
  const pages = Math.max(
    (raw.match(/\/Type\s*\/Page[^sA-Za-z]/g) ?? []).length,
    Number(/\/Count\s+(\d+)/.exec(raw)?.[1] ?? 0) || 0,
  );
  const encrypted = /\/Encrypt[\s/<]/.test(raw);
  const version = /%PDF-(\d\.\d)/.exec(head)?.[1] ?? '?';
  const hasJs = /\/JavaScript\b|\/JS\b\s*[<(]/.test(raw);
  const hasLaunch = /\/Launch\b|\/OpenAction\b/.test(raw);
  const hasEmbedded = /\/EmbeddedFile\b|\/Filespec\b/.test(raw);

  const streams = inflateStreams(buffer);
  let extracted = '';
  for (const st of streams.slice(0, 400)) {
    if (!/Tj|TJ|BT/.test(st.toString('latin1').slice(0, 200000))) continue;
    extracted += extractTextOperators(st) + '\n';
    if (extracted.length > 400000) break;
  }
  const text = extracted.replace(/\s+\n/g, '\n').replace(/[ \t]{2,}/g, ' ').trim();
  const findings = [];
  if (encrypted) findings.push({ level: 'warning', message: 'PDF chiffré : extraction de texte non réalisée.' });
  if (hasJs) findings.push({ level: 'critical', message: 'PDF contenant du JavaScript embarqué : à ne pas ouvrir dans un lecteur non isolé.' });
  if (hasLaunch) findings.push({ level: 'critical', message: 'PDF avec action automatique (Launch/OpenAction) détectée.' });
  if (hasEmbedded) findings.push({ level: 'warning', message: 'PDF avec fichiers embarqués.' });
  if (!text && !encrypted) findings.push({ level: 'info', message: 'Aucun texte extractible : PDF probablement scanné (il faudrait un moteur OCR, cf. docs/ARCHITECTURE.md).' });

  const metrics = {
    pages: pages || undefined,
    version,
    bytes: buffer.length,
    textCharacters: charCount(text),
    words: wordCount(text),
    streams: streams.length,
  };
  const secrets = scanPatterns(text, SECRET_PATTERNS);
  if (secrets.length) findings.push({ level: 'critical', message: 'Secrets potentiels dans le texte du PDF.', values: redactHits(secrets) });

  return {
    status: text ? (encrypted ? 'partial' : 'ok') : 'partial',
    kind: 'pdf',
    extraction: 'heuristique (pas de moteur PDF complet)',
    text: text.slice(0, MAX_TEXT),
    metrics,
    findings,
    summary: buildSummary({ kind: `PDF v${version}`, metrics, findings, extra: `${pages || '?'} page(s)` }),
  };
}

/* -------------------------------------------------------------------- image */

export function analyzeImage(buffer, ext) {
  const dims = (() => {
    try {
      if (ext === '.png' && buffer.length > 24) return { width: buffer.readUInt32BE(16), height: buffer.readUInt32BE(20) };
      if (ext === '.gif' && buffer.length > 10) return { width: buffer.readUInt16LE(6), height: buffer.readUInt16LE(8) };
      if (ext === '.bmp' && buffer.length > 26) return { width: buffer.readInt32LE(18), height: Math.abs(buffer.readInt32LE(22)) };
      if (ext === '.webp' && buffer.length > 30) {
        const fourcc = buffer.subarray(12, 16).toString('latin1');
        if (fourcc === 'VP8X') return { width: 1 + buffer.readUIntLE(24, 3), height: 1 + buffer.readUIntLE(27, 3) };
        if (fourcc === 'VP8 ') return { width: buffer.readUInt16LE(26) & 0x3fff, height: buffer.readUInt16LE(28) & 0x3fff };
      }
      if ((ext === '.jpg' || ext === '.jpeg') && buffer.length > 4) {
        let p = 2;
        while (p + 9 < buffer.length) {
          if (buffer[p] !== 0xff) {
            p += 1;
            continue;
          }
          const marker = buffer[p + 1];
          const len = buffer.readUInt16BE(p + 2);
          if (marker >= 0xc0 && marker <= 0xcf && ![0xc4, 0xc8, 0xcc].includes(marker)) {
            return { height: buffer.readUInt16BE(p + 5), width: buffer.readUInt16BE(p + 7), components: buffer[p + 9] };
          }
          p += 2 + len;
        }
      }
    } catch {
      /* ignore malformed headers */
    }
    return {};
  })();
  return {
    status: 'ok',
    kind: 'image',
    text: '',
    metrics: { ...dims, bytes: buffer.length, format: ext.replace('.', '').toUpperCase() },
    findings: [
      { level: 'info', message: 'Image analysée structurellement uniquement : aucun OCR intégré à cette version (voir docs/ARCHITECTURE.md, « Video/OCR Agent »).' },
    ],
    structure: { ...dims },
    summary: `Image ${ext.replace('.', '').toUpperCase()} ${dims.width ?? '?'}×${dims.height ?? '?'} (${(buffer.length / 1024).toFixed(1)} Ko).`,
  };
}

/* ---------------------------------------------------------------- dispatcher */

export function analyzeBuffer(buffer, ext) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) throw badRequest('Contenu vide : rien à analyser.');
  const e = String(ext ?? '').toLowerCase();
  switch (e) {
    case '.docx':
      return analyzeDocx(buffer);
    case '.xlsx':
      return analyzeXlsx(buffer);
    case '.pdf':
      return analyzePdf(buffer);
    case '.csv':
    case '.tsv':
      return analyzeCsv(buffer);
    case '.json':
      return analyzeJson(buffer);
    case '.md':
      return analyzeMarkdown(buffer);
    case '.png':
    case '.jpg':
    case '.jpeg':
    case '.gif':
    case '.webp':
    case '.bmp':
      return analyzeImage(buffer, e);
    case '.txt':
    case '.log':
    case '.yml':
    case '.yaml':
    case '.xml':
      return analyzeText(buffer, e);
    default:
      throw new AppError(415, 'UNSUPPORTED_ANALYSIS', `Analyse non disponible pour ce type (${e || 'inconnu'}).`);
  }
}

function buildSummary({ kind, metrics, findings, extra }) {
  const bits = [`${kind} analysé`];
  if (extra) bits.push(extra);
  if (metrics.words) bits.push(`${metrics.words} mot(s)`);
  if (metrics.characters) bits.push(`${metrics.characters} caractère(s)`);
  if (metrics.rows !== undefined) bits.push(`${metrics.rows} ligne(s)`);
  if (metrics.columns !== undefined) bits.push(`${metrics.columns} colonne(s)`);
  if (metrics.pages) bits.push(`${metrics.pages} page(s)`);
  if (metrics.paragraphs) bits.push(`${metrics.paragraphs} paragraphe(s)`);
  if (metrics.headings) bits.push(`${metrics.headings} titre(s)`);
  bits.push(`${findings.length} observation(s)`);
  return `${bits.join(', ')}.`;
}

export { SECRET_PATTERNS, PII_PATTERNS, scanPatterns };
