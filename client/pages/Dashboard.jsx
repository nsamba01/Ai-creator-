import { api } from '../api.js';
import { useAuth } from '../auth.jsx';
import { Badge, Card, ErrorNote, Stat, Table, Toolbar, useLoader } from '../ui.jsx';

const fmtBytes = (n) => (n ? `${(n / 1024 / 1024).toFixed(2)} Mo` : '0 Mo');

export default function Dashboard() {
  const { user, isAdmin } = useAuth();
  const { data, error, loading } = useLoader(() => api.get('/api/admin/dashboard'), []);

  if (error) return <ErrorNote error={error} />;
  if (loading || !data) return <p className="muted">Chargement du tableau de bord…</p>;

  if (data.scope === 'self') {
    return (
      <>
        <Card title={`Bonjour ${data.self ? user?.displayName ?? user?.username : ''}`} subtitle="Vue utilisateur : vos fichiers, vos sessions, vos tâches.">
          <div className="stats">
            <Stat label="Mes fichiers" value={data.self.files.total} hint={fmtBytes(data.self.files.bytes)} />
            <Stat label="Mes sessions actives" value={data.self.sessions.total} />
            <Stat label="Tâches assignées" value={data.self.tasks.total} />
          </div>
          <Table
            columns={[
              { key: 'occurred_at', label: 'Horodatage', width: '190px' },
              { key: 'action', label: 'Événement' },
              { key: 'outcome', label: 'Résultat', width: '110px', render: (r) => <Badge tone={r.outcome === 'success' ? 'ok' : 'warn'}>{r.outcome}</Badge> },
            ]}
            rows={data.self.myRecent}
            empty="Aucun événement récent."
          />
        </Card>
        <Card title="Agents orchestrés" subtitle="État du plan de travail PrinceNsamba.">
          <Table
            columns={[
              { key: 'name', label: 'Agent' },
              { key: 'mission', label: 'Mission', render: (r) => <span className="muted">{r.mission}</span> },
              { key: 'active', label: 'En cours', width: '90px' },
              { key: 'queued', label: 'En file', width: '90px' },
              { key: 'done', label: 'Terminées', width: '100px' },
            ]}
            rows={data.agents}
            keyField="key"
          />
        </Card>
      </>
    );
  }

  const o = data.overview;
  return (
    <>
      <div className="stats">
        <Stat label="Utilisateurs" value={o.users.total} hint={`${o.users.active} actifs · ${o.users.disabled} désactivés`} />
        <Stat label="Sessions actives" value={o.sessions.active} hint={`${o.sessions.users} utilisateur(s)`} tone="default" />
        <Stat label="Événements d’audit (24 h)" value={o.audit24h.total} hint={`${o.audit24h.denied} refus/blocages`} tone={o.audit24h.critical ? 'warn' : 'default'} />
        <Stat label="Fichiers" value={o.files.total} hint={fmtBytes(o.files.bytes)} />
        <Stat label="Tâches agents" value={o.tasks.total} hint={`${o.tasks.running} en cours · ${o.tasks.done} terminées`} />
        <Stat label="Score sécurité" value={`${data.posture.score}%`} tone={data.posture.score >= 80 ? 'ok' : 'warn'} hint={`${data.posture.checks.filter((c) => !c.ok).length} point(s) à corriger`} />
      </div>

      <Toolbar>
        <Badge tone={isAdmin ? 'ok' : 'neutral'}>périmètre administrateur</Badge>
        <Badge tone="neutral">{o.users.mustChangePassword} compte(s) à mot de passe initial</Badge>
        <Badge tone={o.users.locked ? 'warn' : 'neutral'}>{o.users.locked} compte(s) verrouillé(s)</Badge>
        {o.sessions.expired ? <Badge tone="warn">{o.sessions.expired} session(s) expirée(s) en base</Badge> : null}
      </Toolbar>

      <div className="grid-2">
        <Card title="Activité récente" dense subtitle="Journal d’audit (aucun secret n’y est enregistré).">
          <Table
            columns={[
              { key: 'occurred_at', label: 'Quand', width: '170px' },
              { key: 'actor_label', label: 'Acteur' },
              { key: 'action', label: 'Action' },
              {
                key: 'outcome',
                label: 'Résultat',
                width: '100px',
                render: (r) => <Badge tone={r.outcome === 'success' ? 'ok' : r.outcome === 'blocked' ? 'warn' : 'danger'}>{r.outcome}</Badge>,
              },
            ]}
            rows={o.recentEvents}
            keyField="occurred_at"
          />
        </Card>
        <Card title="Actions les plus fréquentes (24 h)" dense>
          <Table
            columns={[
              { key: 'action', label: 'Action' },
              { key: 'outcome', label: 'Résultat', width: '100px' },
              { key: 'c', label: 'Occurrences', width: '110px', className: 'num' },
            ]}
            rows={o.topActions}
            keyField="action"
            empty="Aucune activité sur la période."
          />
        </Card>
      </div>

      <Card title="Contrôles de sécurité" subtitle="Calculés côté serveur à partir de la base et de la configuration." dense>
        <ul className="checks">
          {data.posture.checks.map((c) => (
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

      <Card title="Agents" subtitle="Répartition des tâches par rôle." dense>
        <Table
          columns={[
            { key: 'name', label: 'Agent' },
            { key: 'totalTasks', label: 'Tâches', width: '90px', className: 'num' },
            { key: 'active', label: 'En cours', width: '90px', className: 'num' },
            { key: 'queued', label: 'En file', width: '90px', className: 'num' },
            { key: 'done', label: 'Terminées', width: '100px', className: 'num' },
          ]}
          rows={data.agents}
          keyField="key"
        />
      </Card>
    </>
  );
}
