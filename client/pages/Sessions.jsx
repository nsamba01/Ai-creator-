import { useState } from 'react';
import { api } from '../api.js';
import { useAuth } from '../auth.jsx';
import { Badge, Button, Card, ErrorNote, InfoNote, Table, Toolbar, useLoader } from '../ui.jsx';

export default function Sessions() {
  const { can, logout, user } = useAuth();
  const { data, error, reload } = useLoader(() => api.get('/api/sessions'), []);
  const [busy, setBusy] = useState(false);
  const [localError, setLocalError] = useState(null);

  const act = async (fn) => {
    setBusy(true);
    setLocalError(null);
    try {
      await fn();
      await reload(true);
    } catch (err) {
      setLocalError(err);
    } finally {
      setBusy(false);
    }
  };

  const rows = data?.items ?? [];

  return (
    <Card
      title="Sessions actives"
      subtitle="Portée : vos sessions, ou toutes les sessions avec la permission sessions:read:any."
      actions={
        <Toolbar>
          <Button variant="danger" loading={busy} onClick={() => act(() => api.post('/api/sessions/revoke-all', {}).then(logout))}>
            Couper mes sessions
          </Button>
          {can('admin:access') ? <Button variant="secondary" onClick={() => act(() => api.post('/api/sessions/purge', {}))}>Purger les expirées</Button> : null}
        </Toolbar>
      }
    >
      <ErrorNote error={localError ?? error} />
      <InfoNote tone="info">
        Une session expire côté serveur ({Math.round((data?.ttlMs ?? 3600000) / 60000)} min inactivité) et est invalidée à tout changement de mot de
        passe ou de rôle. L’IP n’est jamais stockée en clair, uniquement une empreinte HMAC.
      </InfoNote>
      <Table
        columns={[
          { key: 'current', label: 'Session', width: '110px', render: (s) => (s.current ? <Badge tone="ok">vous</Badge> : <Badge tone="neutral">autre</Badge>) },
          { key: 'email', label: 'Utilisateur', render: (s) => `${s.email} (${s.username})` },
          { key: 'createdAt', label: 'Ouverte le' },
          { key: 'lastSeenAt', label: 'Dernière activité' },
          { key: 'expiresAt', label: 'Expire le' },
          { key: 'ipHash', label: 'Empreinte IP', render: (s) => <code className="muted small">{String(s.ipHash ?? '').slice(0, 22)}…</code> },
          ...(can('sessions:revoke:any')
            ? [
                {
                  key: 'revoke',
                  label: '',
                  width: '110px',
                  render: (s) => (
                    <Button variant="ghost" disabled={s.current} onClick={() => act(() => api.del(`/api/sessions/${encodeURIComponent(s.id)}`))}>
                      Révoquer
                    </Button>
                  ),
                },
              ]
            : []),
        ]}
        rows={rows}
        empty="Aucune session active."
      />
    </Card>
  );
}
