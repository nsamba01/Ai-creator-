import { useState } from 'react';
import { api } from '../api.js';
import { Badge, Button, Card, ErrorNote, InfoNote, Table, Tabs, Textarea, Toolbar, useLoader } from '../ui.jsx';

const LEVEL_TONE = { critical: 'danger', warning: 'warn', notice: 'neutral', info: 'neutral' };

export default function Documents() {
  const [tab, setTab] = useState('inline');
  return (
    <>
      <Card title="Agent documentaire" subtitle="Extraction, mesure et détection d’anomalies : TXT, MD, JSON, CSV/TSV, DOCX, XLSX, PDF, images.">
        <Tabs
          active={tab}
          onChange={setTab}
          tabs={[
            { id: 'inline', label: 'Analyser un contenu' },
            { id: 'history', label: 'Historique' },
          ]}
        />
        {tab === 'inline' ? <InlineAnalyzer /> : <History />}
      </Card>
    </>
  );
}

function InlineAnalyzer() {
  const [content, setContent] = useState('id;nom;salaire\n1;Alice;3200\n2;Bob;\n3;Alice;3200\n');
  const [extension, setExtension] = useState('.csv');
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      const out = await api.post('/api/documents/inline', { content, extension });
      setResult(out);
    } catch (err) {
      setError(err);
      setResult(null);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid-2">
      <div className="stack">
        <Toolbar>
          <select className="input select" value={extension} onChange={(e) => setExtension(e.target.value)} aria-label="type de document">
            {['.csv', '.tsv', '.json', '.md', '.txt', '.xml', '.yml'].map((x) => (
              <option key={x} value={x}>
                {x}
              </option>
            ))}
          </select>
          <Button onClick={run} loading={busy}>
            Analyser
          </Button>
        </Toolbar>
        <Textarea value={content} onChange={(e) => setContent(e.target.value)} rows={16} spellCheck="false" />
        <p className="muted small">
          L’analyse des fichiers binaires (DOCX/XLSX/PDF) passe par l’onglet Fichiers&nbsp;: téléversez, puis analysez par identifiant — le serveur
          vérifie la signature binaire avant tout traitement.
        </p>
      </div>
      <div className="stack">
        <ErrorNote error={error} />
        {result ? <Report result={result} /> : <InfoNote tone="info">Aucune analyse lancée.</InfoNote>}
      </div>
    </div>
  );
}

export function Report({ result }) {
  const findings = result.findings ?? [];
  return (
    <>
      <Card dense title={result.summary} subtitle={`${result.kind} · ${result.bytes} octet(s) · extraction ${result.extraction}`}>
        <Toolbar>
          <Badge tone={result.status === 'ok' ? 'ok' : result.status === 'partial' ? 'warn' : 'danger'}>statut&nbsp;: {result.status}</Badge>
          <Badge tone="neutral">{findings.length} observation(s)</Badge>
          {result.analysisId ? <Badge tone="neutral">analyse #{result.analysisId}</Badge> : null}
        </Toolbar>
        {findings.length ? (
          <ul className="findings">
            {findings.map((f, i) => (
              <li key={i} className={`finding finding-${f.level}`}>
                <Badge tone={LEVEL_TONE[f.level] ?? 'neutral'}>{f.level}</Badge> <span>{f.message}</span>
                {f.values ? (
                  <ul className="muted small">
                    {f.values.map((v, j) => (
                      <li key={j}>
                        {v.type} × {v.occurrences} <em>(valeurs non affichées)</em>
                      </li>
                    ))}
                  </ul>
                ) : null}
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted">Aucune anomalie détectée.</p>
        )}
      </Card>
      <Card dense title="Métriques">
        <pre className="code-block">{JSON.stringify(result.metrics ?? {}, null, 2)}</pre>
      </Card>
      {result.structure ? (
        <Card dense title="Structure">
          <pre className="code-block">{JSON.stringify(result.structure, null, 2).slice(0, 4000)}</pre>
        </Card>
      ) : null}
    </>
  );
}

function History() {
  const { data, error } = useLoader(() => api.get('/api/documents?limit=50'), []);
  return (
    <>
      <ErrorNote error={error} />
      <Table
        columns={[
          { key: 'createdAt', label: 'Date', width: '175px' },
          { key: 'fileName', label: 'Document' },
          { key: 'extension', label: 'Type', width: '90px', render: (r) => <Badge tone="neutral">{r.extension}</Badge> },
          { key: 'source', label: 'Source', width: '90px' },
          {
            key: 'status',
            label: 'Statut',
            width: '100px',
            render: (r) => <Badge tone={r.status === 'ok' ? 'ok' : r.status === 'partial' ? 'warn' : 'danger'}>{r.status}</Badge>,
          },
          { key: 'summary', label: 'Résumé' },
          { key: 'findings', label: 'Observations', width: '110px', className: 'num', render: (r) => r.findings?.length ?? 0 },
        ]}
        rows={data?.items ?? []}
        empty="Aucune analyse enregistrée."
      />
    </>
  );
}
