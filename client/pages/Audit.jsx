import { useState } from 'react';
import { api, qs } from '../api.js';
import { Badge, Button, Card, ErrorNote, InfoNote, Input, Select, Table, Toolbar, useDebounced, useLoader } from '../ui.jsx';

const SEVERITIES = ['debug', 'info', 'notice', 'warning', 'critical'];
const TONE = { critical: 'danger', warning: 'warn', notice: 'neutral', info: 'neutral', debug: 'neutral' };

export default function Audit() {
  const [filters, setFilters] = useState({ action: '', severity: '', category: '', outcome: '', q: '' });
  const debouncedQ = useDebounced(filters.q);
  const query = { ...filters, q: debouncedQ, limit: 100 };
  const { data, error, reload } = useLoader(() => api.get(`/api/admin/audit${qs(query)}`), [query.action, query.severity, query.category, query.outcome, debouncedQ]);

  return (
    <Card
      title="Journal d’audit"
      subtitle="Append-only : les triggers SQL bloquent UPDATE et DELETE. Les valeurs sensibles sont filtrées avant écriture."
      actions={
        <Button variant="ghost" onClick={() => reload()}>
          Rafraîchir
        </Button>
      }
    >
      {data?.stats ? (
        <Toolbar>
          <Badge tone="neutral">{data.total} entrée(s)</Badge>
          <Badge tone={data.stats.failures ? 'warn' : 'neutral'}>{data.stats.failures} échec(s)/blocage(s) sur 24 h</Badge>
          <Badge tone={data.stats.critical ? 'danger' : 'neutral'}>{data.stats.critical} critique(s) sur 24 h</Badge>
          {data.stats.lastEventAt ? <span className="muted small">dernier événement&nbsp;: {new Date(data.stats.lastEventAt).toLocaleString('fr-FR')}</span> : null}
        </Toolbar>
      ) : null}

      <Toolbar>
        <Input placeholder="Recherche libre (acteur, action, détail)…" value={filters.q} onChange={(e) => setFilters({ ...filters, q: e.target.value })} style={{ minWidth: 280 }} />
        <Select value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value })}>
          <option value="">Toute sévérité</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </Select>
        <Select value={filters.outcome} onChange={(e) => setFilters({ ...filters, outcome: e.target.value })}>
          <option value="">Tout résultat</option>
          {['success', 'failure', 'blocked', 'error'].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </Select>
        <Select value={filters.category} onChange={(e) => setFilters({ ...filters, category: e.target.value })}>
          <option value="">Toute catégorie</option>
          {['auth', 'admin', 'security', 'files', 'agents', 'system', 'users'].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </Select>
      </Toolbar>
      <ErrorNote error={error} />
      <InfoNote tone="info">Aucun mot de passe, hash, jeton ou cookie n’est enregistré : la journalisation passe par un filtre de suppression.</InfoNote>

      <Table
        columns={[
          { key: 'occurredAt', label: 'Horodatage', width: '175px', render: (r) => <span className="mono small">{new Date(r.occurredAt).toLocaleString('fr-FR')}</span> },
          { key: 'actorLabel', label: 'Acteur', width: '180px' },
          { key: 'action', label: 'Action', render: (r) => <code>{r.action}</code> },
          { key: 'target', label: 'Cible', width: '130px', render: (r) => (r.targetType ? `${r.targetType} #${r.targetId}` : <span className="muted">—</span>) },
          { key: 'outcome', label: 'Résultat', width: '100px', render: (r) => <Badge tone={r.outcome === 'success' ? 'ok' : r.outcome === 'blocked' ? 'warn' : 'danger'}>{r.outcome}</Badge> },
          { key: 'severity', label: 'Sévérité', width: '100px', render: (r) => <Badge tone={TONE[r.severity]}>{r.severity}</Badge> },
          {
            key: 'detail',
            label: 'Détail',
            width: '240px',
            render: (r) => (r.detail ? <code className="muted small">{JSON.stringify(r.detail).slice(0, 160)}</code> : <span className="muted">—</span>),
          },
        ]}
        rows={data?.items ?? []}
        empty="Aucun événement."
      />
    </Card>
  );
}
