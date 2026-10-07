import { useState } from 'react';
import { api, qs } from '../api.js';
import { useAuth } from '../auth.jsx';
import { Badge, Button, Card, ErrorNote, Field, InfoNote, Input, Select, Table, Tabs, Textarea, Toolbar, useLoader } from '../ui.jsx';

const STATUS_TONE = { done: 'ok', running: 'warn', queued: 'neutral', review: 'neutral', blocked: 'danger', failed: 'danger', cancelled: 'neutral' };

export default function Agents() {
  const { can } = useAuth();
  const [tab, setTab] = useState('board');
  const [status, setStatus] = useState('');
  const meta = useLoader(() => api.get('/api/agents'), []);
  const tasks = useLoader(() => api.get(`/api/agents/tasks${qs({ status, limit: 100 })}`), [status]);
  const [creating, setCreating] = useState(false);
  const [localError, setLocalError] = useState(null);

  const canUpdate = can('agents:update');

  const patch = async (id, body) => {
    setLocalError(null);
    try {
      await api.patch(`/api/agents/tasks/${id}`, body);
      await tasks.reload(true);
      await meta.reload(true);
    } catch (err) {
      setLocalError(err);
    }
  };

  return (
    <>
      <Card title="Agents IA" subtitle="Rôles spécialisés et tableau de bord partagé (principe de moindre privilège par rôle)." actions={canUpdate ? <Button onClick={() => setCreating(true)}>Nouvelle tâche</Button> : null}>
        <ErrorNote error={localError ?? meta.error ?? tasks.error} />
        <Tabs
          active={tab}
          onChange={setTab}
          tabs={[
            { id: 'board', label: 'Tableau des tâches', count: tasks.data?.total },
            { id: 'roles', label: 'Rôles', count: meta.data?.agents?.length },
            { id: 'workflow', label: 'Flux' },
          ]}
        />

        {tab === 'board' ? (
          <>
            <Toolbar>
              <Select value={status} onChange={(e) => setStatus(e.target.value)}>
                <option value="">Tous les statuts</option>
                {['queued', 'running', 'review', 'blocked', 'done', 'failed', 'cancelled'].map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </Select>
              <Button variant="ghost" onClick={() => tasks.reload()}>
                Rafraîchir
              </Button>
            </Toolbar>
            <Table
              columns={[
                { key: 'ref', label: 'Réf.', width: '90px', render: (t) => <code>{t.ref}</code> },
                { key: 'title', label: 'Tâche', render: (t) => <div><strong>{t.title}</strong>{t.description ? <br /> : null}{t.description ? <span className="muted small">{t.description}</span> : null}</div> },
                { key: 'agentRole', label: 'Agent', width: '130px', render: (t) => <Badge tone="neutral">{t.agentRole}</Badge> },
                { key: 'priority', label: 'Priorité', width: '100px', render: (t) => <Badge tone={t.priority === 'critical' ? 'danger' : t.priority === 'high' ? 'warn' : 'neutral'}>{t.priority}</Badge> },
                { key: 'status', label: 'Statut', width: '110px', render: (t) => <Badge tone={STATUS_TONE[t.status] ?? 'neutral'}>{t.status}</Badge> },
                ...(canUpdate
                  ? [
                      {
                        key: 'actions',
                        label: '',
                        width: '230px',
                        render: (t) => (
                          <Toolbar>
                            {t.status !== 'running' ? <Button variant="ghost" onClick={() => patch(t.id, { status: 'running' })}>Démarrer</Button> : null}
                            {t.status !== 'review' ? <Button variant="ghost" onClick={() => patch(t.id, { status: 'review' })}>Second avis</Button> : null}
                            {t.status !== 'done' ? <Button variant="secondary" onClick={() => patch(t.id, { status: 'done' })}>Clôturer</Button> : null}
                          </Toolbar>
                        ),
                      },
                    ]
                  : []),
              ]}
              rows={tasks.data?.items ?? []}
              empty="Aucune tâche. Le tableau de bord est vide au premier lancement."
            />
          </>
        ) : null}

        {tab === 'roles' ? (
          <div className="grid-2">
            {(meta.data?.agents ?? []).map((a) => (
              <Card key={a.key} dense title={a.name} subtitle={a.mission}>
                <Toolbar>
                  <Badge tone="neutral">{a.totalTasks} tâche(s)</Badge>
                  <Badge tone={a.active ? 'warn' : 'neutral'}>{a.active} en cours</Badge>
                  <Badge tone="ok">{a.done} terminées</Badge>
                </Toolbar>
                <p className="muted small">
                  Permissions requises&nbsp;: {a.permissions.map((p) => <code key={p}>{p}</code>).join(' ') || 'aucune'}
                </p>
              </Card>
            ))}
          </div>
        ) : null}

        {tab === 'workflow' ? (
          <ol className="workflow">
            {(meta.data?.workflow ?? []).map((step, i) => (
              <li key={step}>
                <span className="step-num">{i + 1}</span>
                {step}
              </li>
            ))}
          </ol>
        ) : null}
      </Card>

      {creating ? (
        <CreateTask
          roles={meta.data?.agents ?? []}
          onClose={() => setCreating(false)}
          onCreated={async () => {
            await tasks.reload(true);
            await meta.reload(true);
            setCreating(false);
          }}
        />
      ) : null}
    </>
  );
}

function CreateTask({ roles, onClose, onCreated }) {
  const [form, setForm] = useState({ title: '', agentRole: 'developpeur', priority: 'normal', description: '' });
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.post('/api/agents/tasks', form);
      await onCreated();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modalish title="Tâche pour un agent" onClose={onClose}>
      <ErrorNote error={error} />
      <form className="stack" onSubmit={submit}>
        <Field label="Titre" required>
          <Input value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} required minLength={4} maxLength={200} />
        </Field>
        <Toolbar>
          <Field label="Agent">
            <Select value={form.agentRole} onChange={(e) => setForm({ ...form, agentRole: e.target.value })}>
              {roles.map((r) => (
                <option key={r.key} value={r.key}>
                  {r.name}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Priorité">
            <Select value={form.priority} onChange={(e) => setForm({ ...form, priority: e.target.value })}>
              {['low', 'normal', 'high', 'critical'].map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </Select>
          </Field>
        </Toolbar>
        <Field label="Description">
          <Textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} rows={5} />
        </Field>
        <Button type="submit" loading={busy}>
          Créer la tâche
        </Button>
      </form>
    </Modalish>
  );
}

function Modalish({ title, children, onClose }) {
  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title}>
        <header>
          <h3>{title}</h3>
          <button className="link" onClick={onClose} aria-label="Fermer">
            ✕
          </button>
        </header>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}
