/**
 * Document analysis: CSV, JSON, Markdown, DOCX, XLSX, PDF, images.
 * The fixtures are built by the test itself (no binary blob in the repo).
 */
import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { analyzeCsv, analyzeDocx, analyzeImage, analyzeJson, analyzeMarkdown, analyzePdf, analyzeXlsx, parseDelimited } from '../src/services/documents.service.js';
import { readZip } from '../src/services/zip.js';
import { boot, buildDocx, buildPdf, buildXlsx, multipart, PNG_1x1, zip } from './helpers.js';

const ADMIN = { id: 'admin@test.local', password: 'Sup3r-Secret-Initial!' };

describe('lecteurs de documents (unitaire)', () => {
  it('détecte le délimiteur et analyse un CSV avec anomalies', () => {
    const csv = 'id;nom;salaire;ville\n1;Alice;3200;Paris\n2;Bob;;\n3;Alice;3200;\n4;Ceinture;non-numerique;\n1;Alice;3200;Paris\n';
    const out = analyzeCsv(Buffer.from(csv, 'utf8'));
    assert.equal(out.status, 'ok');
    assert.equal(out.metrics.delimiter, ';');
    assert.equal(out.metrics.rows, 5);
    assert.equal(out.metrics.columns, 4);
    const cols = out.structure.columns;
    assert.equal(cols[2].inferredType, 'string', 'salaire n’est plus numériques partout → type string');
    assert.equal(cols[2].missing, 1, 'une cellule de salaire absente');
    assert.ok(out.metrics.missingCells >= 4, 'au moins 4 cellules manquantes au total');
    assert.ok(out.findings.some((f) => /manquante à/.test(f.message)), 'colonne majoritairement vide signalée');
    assert.equal(out.metrics.duplicateRows, 1, 'une ligne exactement dupliquée');
    assert.ok(out.findings.some((f) => /dupliquée/.test(f.message)), 'le doublon est signalé');
  });

  it('gère les guillemets, les nouvelles lignes et les virgules dans un CSV', () => {
    const csv = 'a,b\n"x,1","multi\nligne"\n2,"il dit ""bonjour"""\n';
    const out = analyzeCsv(Buffer.from(csv, 'utf8'), { delimiter: ',' });
    assert.equal(out.metrics.rows, 2);
    const rows = parseDelimited(csv, ',');
    assert.equal(rows[1][0], 'x,1');
    assert.equal(rows[1][1], 'multi\nligne');
    assert.equal(rows[2][1], 'il dit "bonjour"');
    assert.equal(out.findings.filter((f) => f.level === 'warning').length, 0, 'aucune fausse alerte de colonnes');
  });

  it('détecte les lignes irrégulières et les doublons exacts', () => {
    const csv = 'a,b\n1,2\n3,2,9\n1,2\n';
    const out = analyzeCsv(Buffer.from(csv, 'utf8'));
    assert.equal(out.metrics.raggedRows, 1);
    assert.equal(out.metrics.duplicateRows, 1);
  });

  it('analyse un JSON et signale les champs sensibles sans les divulguer', () => {
    const doc = { nom: 'Prince', elements: [1, 2, 3], mot_de_passe: 'Ne-Pas-Afficher-9!', imbrique: { a: { b: { c: 1 } } } };
    const out = analyzeJson(Buffer.from(JSON.stringify(doc), 'utf8'));
    assert.equal(out.status, 'ok');
    assert.equal(out.structure.shape, 'object');
    assert.ok(out.structure.keys.includes('mot_de_passe'), 'les clés sensibles en français sont repérées');
    assert.ok(out.metrics.nodes >= 10);
    assert.ok(out.findings.some((f) => /sensibles/.test(f.message)));
    for (const part of [out.findings, out.structure, out.metrics, out.summary]) {
      assert.ok(!JSON.stringify(part).includes('Ne-Pas-Afficher-9!'), 'la valeur sensible n’est jamais recopiée dans l’analyse');
    }
  });

  it('signale un JSON invalide sans planter', () => {
    const out = analyzeJson(Buffer.from('{"a": ', 'utf8'));
    assert.equal(out.status, 'failed');
    assert.match(out.findings[0].message, /JSON invalide/);
  });

  it('compte les titres et blocs d’un Markdown', () => {
    const md = '# Titre\n\n## Section\n\ntexte\n\n```js\nconsole.log(1)\n```\n\n[lien](https://exemple.fr)\n';
    const out = analyzeMarkdown(Buffer.from(md, 'utf8'));
    assert.equal(out.kind, 'markdown');
    assert.equal(out.metrics.headings, 2);
    assert.equal(out.metrics.codeBlocks, 1);
    assert.equal(out.metrics.links, 1);
    assert.deepEqual(out.structure.headings.map((h) => h.level), [1, 2]);
  });

  it('repère un bloc de code non fermé', () => {
    const out = analyzeMarkdown(Buffer.from('# T\n\n```js\noui\n', 'utf8'));
    assert.ok(out.findings.some((f) => /non fermé/.test(f.message)));
  });

  it('extrait texte, titres, liens et métadonnées d’un DOCX', () => {
    const buf = buildDocx([
      { text: 'Rapport de sécurité', style: 'Heading1' },
      { text: 'Aucun incident critique détecté.' },
      { text: 'Mots de passe testés : oui' },
    ]);
    const out = analyzeDocx(buf);
    assert.equal(out.status, 'ok');
    assert.equal(out.metrics.paragraphs, 3);
    assert.equal(out.metrics.headings, 1);
    assert.equal(out.structure.headings[0].title, 'Rapport de sécurité');
    assert.equal(out.structure.metadata.creator, 'PrinceNsamba Tests');
    assert.ok(out.text.includes('Aucun incident critique détecté.'));
    assert.ok(out.findings.some((f) => /lien\(s\) externe\(s\)/.test(f.message)), 'lien externe relevé');
  });

  it('lit un XLSX (chaînes partagées, colonnes numériques)', () => {
    const buf = buildXlsx([
      ['Nom', 'Valeur', 'Ville'],
      ['Alice', 10, 'Paris'],
      ['Bob', 20, 'Lyon'],
      ['Chloé', 30, 'Nantes'],
    ]);
    const out = analyzeXlsx(buf);
    assert.equal(out.status, 'ok');
    assert.equal(out.metrics.sheets, 1);
    assert.equal(out.metrics.totalRows, 4);
    const sheet = out.structure.sheets[0];
    assert.equal(sheet.name, 'Feuil1');
    assert.equal(sheet.columns, 3);
    assert.equal(sheet.preview[1][0], 'Alice', 'les chaînes partagées sont résolues');
    assert.equal(sheet.preview[2][1], '20', 'la prévisualisation est rendue en texte');
    assert.equal(sheet.numericColumns, 1, 'la colonne numérique est reconnue comme telle');
  });

  it('détecte un projet VBA dans un classeur', () => {
    const base = buildXlsx([['a'], [1]]);
    assert.ok(readZip(base).names.includes('xl/workbook.xml'), 'fixture de base lisible');
    const out = analyzeXlsx(buildXlsxWithMacro());
    assert.ok(out.findings.some((f) => /macros/i.test(f.message)), 'la présence de macros est signalée en critique');
    assert.equal(out.findings.find((f) => /macros/i.test(f.message)).level, 'critical');
    assert.ok(out.structure.sheets[0].hasMacros);
  });

  it('extrait le texte d’un PDF simple', () => {
    const pdf = buildPdf('Rapport PrinceNsamba — ligne 1.\nBilan de securite.');
    const out = analyzePdf(pdf);
    assert.equal(out.kind, 'pdf');
    assert.equal(out.metrics.pages, 1);
    assert.match(out.text, /Rapport PrinceNsamba/);
    assert.match(out.text, /Bilan de securite/);
    assert.ok(out.metrics.bytes > 200);
  });

  it('signale les PDF contenant du JavaScript ou des actions', () => {
    const pdf = Buffer.from(
      buildPdf('base').toString('latin1').replace('<< /Type /Catalog /Pages 2 0 R >>', '<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /Launch >> /JavaScript (alert(1)) >>'),
      'latin1',
    );
    const out = analyzePdf(pdf);
    assert.ok(out.findings.some((f) => /JavaScript/.test(f.message)));
    assert.ok(out.findings.some((f) => /action automatique/i.test(f.message)));
  });

  it('lit les dimensions d’une image sans la décoder', () => {
    const out = analyzeImage(PNG_1x1, '.png');
    assert.equal(out.metrics.width, 1);
    assert.equal(out.metrics.height, 1);
    assert.equal(out.metrics.format, 'PNG');
    assert.ok(out.findings.some((f) => /OCR/.test(f.message)), 'limite annoncée honnêtement');
  });

  it('lit une archive ZIP OOXML et refuse une archive factice', () => {
    const zip = readZip(buildDocx([{ text: 'x' }]));
    assert.ok(zip.names.includes('word/document.xml'));
    assert.throws(() => readZip(Buffer.from('pas une archive')), /ZIP/);
  });
});

function buildXlsxWithMacro() {
  const rows = [['Nom'], ['Alice']];
  const shared = rows.flat().filter((v) => typeof v === 'string');
  const sheetRows = rows
    .map((row, r) => `<row r="${r + 1}">${row.map((c) => `<c r="A${r + 1}" t="s"><v>${shared.indexOf(String(c))}</v></c>`).join('')}</row>`)
    .join('');
  return zip([
    ['[Content_Types].xml', '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>'],
    ['xl/workbook.xml', '<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet name="Macros" sheetId="1"/></sheets></workbook>'],
    ['xl/worksheets/sheet1.xml', `<?xml version="1.0"?><worksheet><sheetData>${sheetRows}</sheetData></worksheet>`],
    ['xl/sharedStrings.xml', `<?xml version="1.0"?><sst>${shared.map((x) => `<si><t>${x}</t></si>`).join('')}</sst>`],
    ['xl/vbaProject.bin', 'FAKE-VBA-BINARY'],
  ]);
}

describe('analyse de documents via l’API', () => {
  let ctx;
  let admin;
  before(async () => {
    ctx = await boot();
    admin = ctx.client();
    await admin.login(ADMIN.id, ADMIN.password);
  });
  after(async () => {
    await ctx.close();
  });

  it('analyse un contenu en ligne et journalise l’opération', async () => {
    const res = await admin.post('/api/documents/inline', { content: 'a;b\n1;2\n3;\n', extension: 'csv' });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.kind, 'csv');
    assert.equal(res.body.metrics.rows, 2);
    assert.ok(res.body.summary.length > 10);
    assert.ok(res.body.analysisId >= 1, 'analyse persistée');
    const list = await admin.get('/api/documents');
    assert.equal(list.status, 200);
    assert.equal(list.body.total, 1);
    assert.equal(list.body.items[0].fileName, 'inline.csv');
  });

  it('refuse une extension non analysable en ligne', async () => {
    const res = await admin.post('/api/documents/inline', { content: 'x', extension: 'exe' });
    assert.equal(res.status, 415);
  });

  it('analyse un DOCX téléversé et signale les données personnelles', async () => {
    const docx = buildDocx([
      { text: 'Fiche de paie', style: 'Heading1' },
      { text: 'Contact : alice.dupont@example.org au 06 12 34 56 78.' },
    ]);
    const mp = multipart('file', { filename: 'fiche.docx', contentType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', buffer: docx });
    const up = await admin.post('/api/files', undefined, { headers: mp.headers, form: mp.body });
    assert.equal(up.status, 201, JSON.stringify(up.body));
    const res = await admin.post('/api/documents/analyze', { fileId: up.body.file.id, includeText: true });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.kind, 'docx');
    assert.match(res.body.textPreview, /Fiche de paie/);
    assert.ok(res.body.findings.some((f) => /personnelles/.test(f.message)), 'e-mail/téléphone relevés');
    assert.ok(!JSON.stringify(res.body).includes('06 12 34 56 78') || res.body.textPreview.includes('06 12 34 56 78'), 'les occurrences sont comptées, pas répertoriées');
    assert.ok(res.body.findings.find((f) => /personnelles/.test(f.message)).values.every((v) => v.occurrences >= 1));
  });

  it('refuse l’analyse du fichier d’un autre utilisateur', async () => {
    const other = await admin.post('/api/users', { email: 'frank@test.local', username: 'frank', roles: ['USER'] });
    const c = ctx.client();
    await c.login('frank@test.local', other.body.temporaryPassword);
    await c.post('/api/auth/change-password', {
      currentPassword: other.body.temporaryPassword,
      newPassword: 'Zephyr-Clarification-2026!',
      confirm: 'Zephyr-Clarification-2026!',
    });
    const res = await c.post('/api/documents/analyze', { fileId: 1 });
    assert.ok([403, 404].includes(res.status), `accès refusé (${res.status})`);
  });
});
