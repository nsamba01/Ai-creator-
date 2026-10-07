import { api } from '../api.js';
import { Badge, Card, ErrorNote, InfoNote, Stat, Table, Toolbar, useLoader } from '../ui.jsx';

export default function Security() {
  const { data, error, loading } = useLoader(() => api.get('/api/admin/security'), []);
  const risky = useLoader(() => api.get('/api/admin/security/users-at-risk').catch(() => null), []);

  if (loading || !data) return <p className="muted">Évaluation de la sécurité…</p>;
  if (error) return <ErrorNote error={error} />;

  if (data.scope === 'self') {
    return (
      <Card title="Sécurité de mon compte" subtitle="Vos contrôles personnels ; le périmètre complet est réservé aux administrateurs.">
        <ul className="checks">
          {data.checks.map((c) => (
            <li key={c.id} className={c.ok ? 'ok' : 'ko'}>
              <span className="mark">{c.ok ? '✔' : '✖'}</span>
              <span>
                <strong>{c.label}</strong>
                <br />
                <span className="muted">{c.detail}</span>
              </span>
            </li>
          ))}
        </ul>
        <InfoNote tone="info">Sessions actives&nbsp;: {data.mySessions}. Révoquez-les depuis l’onglet Sessions en cas de doute.</InfoNote>
      </Card>
    );
  }

  return (
    <>
      <div className="stats">
        <Stat label="Score global" value={`${data.score}%`} tone={data.score >= 80 ? 'ok' : 'warn'} hint={`${data.checks.filter((c) => !c.ok).length} contrôle(s) insatisfait(s)`} />
        <Stat label="Échecs de connexion (24 h)" value={data.counts.failed} tone={data.counts.failed > 20 ? 'warn' : 'default'} />
        <Stat label="CSRF bloqués (24 h)" value={data.counts.csrfFailures} tone={data.counts.csrfFailures ? 'warn' : 'ok'} />
        <Stat label="Refus d’autorisation (24 h)" value={data.counts.denied} />
        <Stat label="SSRF bloqués" value={data.counts.urlBlocked} tone="ok" />
        <Stat label="Fichiers refusés" value={data.counts.filesRejected} tone="ok" />
      </div>

      {data.warnings?.length ? (
        <Card title="Avertissements" dense>
          <ul className="findings">
            {data.warnings.map((w, i) => (
              <li key={i} className={`finding finding-${w.level}`}>
                <Badge tone={w.level === 'critical' ? 'danger' : w.level === 'warning' ? 'warn' : 'neutral'}>{w.level}</Badge> {w.message}
              </li>
            ))}
          </ul>
        </Card>
      ) : null}

      <Card title="Contrôles" subtitle="Chaque ligne est calculée à partir de la base et de la configuration du serveur — pas d’une déclaration de l’interface.">
        <ul className="checks">
          {data.checks.map((c) => (
            <li key={c.id} className={c.ok ? 'ok' : 'ko'}>
              <span className="mark">{c.ok ? '✔' : '✖'}</span>
              <span>
                <strong>{c.label}</strong>
                <br />
                <span className="muted">{c.detail}</span>
              </span>
            </li>
          ))}
        </ul>
      </Card>

      <div className="grid-2">
        <Card dense title="Paramètres de sécurité appliqués">
          <pre className="code-block">{JSON.stringify(data.config, null, 2)}</pre>
          <InfoNote tone="info">
            Hachage&nbsp;: <code>{data.hashing.algorithm}</code> ({data.hashing.encoding}),{' '}
            {data.hashing.nativeBinding === true ? 'binding natif' : data.hashing.nativeBinding === false ? 'implémentation pur JS' : 'détection en cours'}, aucun
            stockage en clair.
          </InfoNote>
        </Card>
        <Card dense title="Comptes à risque">
          <Table
            columns={[
              { key: 'email', label: 'Compte' },
              { key: 'reason', label: 'Motif' },
              { key: 'detail', label: 'Détail' },
            ]}
            rows={[
              ...(risky.data?.locked ?? []).map((u) => ({ id: `l${u.id}`, email: u.email, reason: 'verrouillé', detail: `jusqu’à ${u.locked_until}` })),
              ...(risky.data?.mustChangePassword ?? []).map((u) => ({ id: `p${u.id}`, email: u.email, reason: 'mot de passe initial', detail: 'changement obligatoire' })),
              ...(risky.data?.inactive ?? []).map((u) => ({ id: `i${u.id}`, email: u.email, reason: 'inactif 90 j+', detail: u.last_login_at ?? 'jamais connecté' })),
            ]}
            empty="Aucun compte à risque."
          />
        </Card>
      </div>

      <Card dense title="Jalons d’anti brute-force (empreintes)">
        <Table
          columns={[
            { key: 'keyFingerprint', label: 'Empreinte du seau', render: (b) => <code>{b.keyFingerprint}</code> },
            { key: 'count', label: 'Tentatives', width: '110px', className: 'num' },
            { key: 'lastAt', label: 'Dernière', width: '190px' },
            { key: 'lockedUntil', label: 'Verrouillé jusqu’à', width: '190px', render: (b) => b.lockedUntil ?? <span className="muted">—</span> },
          ]}
          rows={(data.buckets ?? []).map((b, i) => ({ ...b, id: `${i}` }))}
          empty="Aucun seau actif."
        />
      </Card>
    </>
  );
}
