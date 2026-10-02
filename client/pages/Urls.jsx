import { useState } from 'react';
import { api } from '../api.js';
import { Badge, Button, Card, ErrorNote, Field, InfoNote, Input, Table, Toolbar } from '../ui.jsx';

export default function Urls() {
  const [url, setUrl] = useState('https://example.com/');
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [preflight, setPreflight] = useState(null);

  const analyze = async (e) => {
    e?.preventDefault();
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.post('/api/urls/analyze', { url: url.trim() }));
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const check = async () => {
    setError(null);
    setPreflight(null);
    try {
      setPreflight(await api.post('/api/urls/preflight', { url: url.trim() }));
    } catch (err) {
      setPreflight({ allowed: false, reason: err.message });
    }
  };

  return (
    <Card title="Analyse d’URL" subtitle="Le serveur refuse les hôtes internes, les adresses privées, les ports non listés et les redirections vers ces cibles (anti-SSRF).">
      <form onSubmit={analyze} className="stack">
        <Toolbar>
          <div style={{ flex: 1, minWidth: 260 }}>
            <Field label="URL à analyser">
              <Input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://exemple.fr/rapport" spellCheck="false" />
            </Field>
          </div>
          <Button type="submit" loading={busy}>
            Analyser
          </Button>
          <Button type="button" variant="ghost" onClick={check}>
            Vérifier la politique
          </Button>
        </Toolbar>
      </form>

      <ErrorNote error={error} onDismiss={() => setError(null)} />
      {preflight ? (
        <InfoNote tone={preflight.allowed ? 'ok' : 'danger'}>
          {preflight.allowed
            ? `Autorisée : ${preflight.scheme}//${preflight.host}:${preflight.port}`
            : `Refusée par la politique : ${preflight.reason}`}
        </InfoNote>
      ) : null}

      {result ? (
        <>
          <Toolbar>
            <Badge tone={result.httpStatus < 400 ? 'ok' : 'warn'}>HTTP {result.httpStatus}</Badge>
            <Badge tone="neutral">{result.contentType}</Badge>
            <Badge tone="neutral">{(result.bytes / 1024).toFixed(1)} Ko</Badge>
            <Badge tone="neutral">{result.redirects} redirection(s)</Badge>
            <Badge tone="neutral">{result.durationMs} ms</Badge>
            <Badge tone="neutral">{result.words} mot(s)</Badge>
          </Toolbar>
          <h4>{result.title ?? '(pas de titre)'}</h4>
          {result.meta?.description ? <p className="muted">{result.meta.description}</p> : null}
          {result.headings?.length ? (
            <ul className="headings">
              {result.headings.map((h, i) => (
                <li key={i} style={{ paddingLeft: `${(h.level - 1) * 14}px` }}>
                  <Badge tone="neutral">h{h.level}</Badge> {h.text}
                </li>
              ))}
            </ul>
          ) : null}
          {result.excerpt ? <pre className="code-block">{result.excerpt}</pre> : null}
          {result.observations?.length ? (
            <Card dense title="Observations">
              <ul className="findings">
                {result.observations.map((o, i) => (
                  <li key={i} className={`finding finding-${o.level}`}>
                    <Badge tone={o.level === 'critical' ? 'danger' : o.level === 'warning' ? 'warn' : 'neutral'}>{o.level}</Badge> {o.message}
                  </li>
                ))}
              </ul>
            </Card>
          ) : null}
          {result.forms?.length ? (
            <Card dense title="Formulaires détectés (audit rapide)">
              <Table
                columns={[
                  { key: 'action', label: 'action' },
                  { key: 'method', label: 'méthode', width: '90px' },
                  { key: 'inputs', label: 'champs', width: '80px', className: 'num' },
                  {
                    key: 'hasCsrfField',
                    label: 'jeton anti-CSRF',
                    width: '140px',
                    render: (f) => (f.hasCsrfField ? <Badge tone="ok">présent</Badge> : <Badge tone="warn">absent</Badge>),
                  },
                ]}
                rows={result.forms}
                keyField="action"
              />
            </Card>
          ) : null}
          <Card dense title="En-têtes de sécurité du serveur distant">
            <pre className="code-block">{JSON.stringify(result.remoteSecurityHeaders ?? {}, null, 2)}</pre>
          </Card>
        </>
      ) : (
        <InfoNote tone="info">
          Exemples de cibles refusées&nbsp;: <code>http://169.254.169.254/latest/meta-data/</code>, <code>http://127.0.0.1:6379</code>,{' '}
          <code>file:///etc/passwd</code>, <code>http://host.docker.internal:3000</code>.
        </InfoNote>
      )}
    </Card>
  );
}
