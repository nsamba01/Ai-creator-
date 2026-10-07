import { useState } from 'react';
import { api, qs } from '../api.js';
import { useAuth } from '../auth.jsx';
import { Badge, Button, Card, ErrorNote, Field, InfoNote, Input, Modal, Select, Table, Toolbar, useDebounced, useLoader } from '../ui.jsx';

const STATUS_TONE = { active: 'ok', disabled: 'danger', pending_password: 'warn', deleted: 'neutral' };

export default function Users() {
  const { can } = useAuth();
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('');
  const [creating, setCreating] = useState(false);
  const [selected, setSelected] = useState(null);
  const debounced = useDebounced(search);
  const [localError, setLocalError] = useState(null);

  const { data, error, reload, loading } = useLoader(() => api.get(`/api/users${qs({ q: debounced, status, limit: 100 })}`), [debounced, status]);

  const canRead = can('users:read');
  const canUpdate = can('users:update');
  const canDisable = can('users:disable');
  const canReset = can('users:reset_password');
  const canDelete = can('users:delete');

  if (!canRead) {
    return <InfoNote tone="warning">La gestion des utilisateurs est réservée aux administrateurs (permission <code>users:read</code>).</InfoNote>;
  }

  const act = async (fn, okMessage) => {
    setLocalError(null);
    try {
      await fn();
      if (okMessage) window.dispatchEvent(new CustomEvent('princesamba:toast', { detail: okMessage }));
      await reload(true);
    } catch (err) {
      setLocalError(err);
    }
  };

  return (
    <>
      <Card
        title="Utilisateurs"
        subtitle="Création, rôles, désactivation, réinitialisation. Le serveur refuse ces opérations sans la permission correspondante."
        actions={<Button onClick={() => setCreating(true)} disabled={!can('users:create')}>Nouvel utilisateur</Button>}
      >
        <Toolbar>
          <Input placeholder="Rechercher (nom, e-mail, identifiant)…" value={search} onChange={(e) => setSearch(e.target.value)} style={{ minWidth: 260 }} />
          <Select value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">Tous les statuts</option>
            <option value="active">Actif</option>
            <option value="disabled">Désactivé</option>
            <option value="pending_password">Mot de passe initial à changer</option>
          </Select>
          <span className="muted small">{data ? `${data.total} résultat(s) · ${data.counts?.admins ?? 0} admin(s)` : '…'}</span>
        </Toolbar>
        <ErrorNote error={localError ?? error} onDismiss={() => setLocalError(null)} />
        <Table
          loading={loading}
          columns={[
            { key: 'id', label: '#', width: '60px', className: 'num' },
            {
              key: 'displayName',
              label: 'Utilisateur',
              render: (u) => (
                <div>
                  <strong>{u.displayName || u.username}</strong>
                  <br />
                  <span className="muted small">{u.email}</span>
                </div>
              ),
            },
            { key: 'username', label: 'Identifiant', width: '140px' },
            { key: 'roles', label: 'Rôles', width: '140px', render: (u) => (u.roles ?? []).map((r) => <Badge key={r} tone={r === 'ADMIN' ? 'danger' : 'neutral'}>{r}</Badge>) },
            { key: 'status', label: 'Statut', width: '130px', render: (u) => <Badge tone={STATUS_TONE[u.status] ?? 'neutral'}>{u.status}</Badge> },
            {
              key: 'lastLoginAt',
              label: 'Dernière connexion',
              width: '170px',
              render: (u) => <span className="muted small">{u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleString('fr-FR') : 'jamais'}</span>,
            },
            {
              key: 'actions',
              label: '',
              width: '220px',
              render: (u) => (
                <div className="row-right">
                  <Button variant="ghost" onClick={() => setSelected(u)}>Détails</Button>
                  {canDisable ? (
                    <Button
                      variant={u.status === 'disabled' ? 'secondary' : 'danger'}
                      onClick={() =>
                        act(
                          () => api.post(`/api/users/${u.id}/status`, { status: u.status === 'disabled' ? 'active' : 'disabled', reason: 'action depuis la console' }),
                          u.status === 'disabled' ? 'Compte réactivé.' : 'Compte désactivé.',
                        )
                      }
                    >
                      {u.status === 'disabled' ? 'Activer' : 'Désactiver'}
                    </Button>
                  ) : null}
                </div>
              ),
            },
          ]}
          rows={data?.items ?? []}
          empty="Aucun utilisateur."
        />
      </Card>

      {creating ? <CreateUserModal roles={data?.roles ?? ['USER']} onClose={() => setCreating(false)} onCreated={() => act(() => Promise.resolve(), 'Utilisateur créé.')} reload={reload} /> : null}
      {selected ? (
        <UserDetailModal
          user={selected}
          permissions={data?.permissions}
          onClose={() => setSelected(null)}
          canUpdate={canUpdate}
          canReset={canReset}
          canDelete={canDelete}
          act={act}
        />
      ) : null}
    </>
  );
}

function CreateUserModal({ roles, onClose, reload }) {
  const [form, setForm] = useState({ email: '', username: '', displayName: '', roles: ['USER'] });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const out = await api.post('/api/users', form);
      setResult(out);
      await reload(true);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title="Créer un utilisateur"
      onClose={onClose}
      footer={result ? <Button onClick={onClose}>Terminer</Button> : <><Button onClick={submit} loading={busy}>Créer</Button> <Button variant="ghost" onClick={onClose}>Annuler</Button></>}
    >
      <ErrorNote error={error} />
      {result ? (
        <div className="stack">
          <InfoNote tone="ok">
            Utilisateur créé. Mot de passe temporaire (affiché <strong>une seule fois</strong>, non stocké en clair, non récupérable depuis la base) :
          </InfoNote>
          <pre className="secret-box">{result.temporaryPassword}</pre>
          <p className="muted small">Transmettez-le hors bande. L’utilisateur devra le changer à sa première connexion.</p>
        </div>
      ) : (
        <form onSubmit={submit} className="stack">
          <Field label="E-mail" required>
            <Input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} required autoComplete="off" />
          </Field>
          <Field label="Identifiant" required hint="2-32 caractères : lettres, chiffres, . _ -">
            <Input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required minLength={2} maxLength={32} />
          </Field>
          <Field label="Nom affiché">
            <Input value={form.displayName} onChange={(e) => setForm({ ...form, displayName: e.target.value })} maxLength={120} />
          </Field>
          <Field label="Rôles" required hint="Aucun mot de passe : un mot de passe temporaire fort est généré par le serveur.">
            <div className="chips">
              {(roles.length ? roles : ['USER']).map((r) => (
                <label key={r} className={`chip${form.roles.includes(r) ? ' on' : ''}`}>
                  <input
                    type="checkbox"
                    checked={form.roles.includes(r)}
                    onChange={(e) => setForm({ ...form, roles: e.target.checked ? [...form.roles, r] : form.roles.filter((x) => x !== r) })}
                  />
                  {r}
                </label>
              ))}
            </div>
          </Field>
        </form>
      )}
    </Modal>
  );
}

function UserDetailModal({ user, onClose, canUpdate, canReset, canDelete, act }) {
  const { data, reload } = useLoader(() => api.get(`/api/users/${user.id}`), [user.id]);
  const detail = data?.user ?? user;
  const [roles, setRoles] = useState(detail.roles ?? ['USER']);
  const [reason, setReason] = useState('');

  return (
    <Modal
      title={`${detail.displayName || detail.username} · #${detail.id}`}
      onClose={onClose}
      footer={
        <>
          {canReset ? <Button variant="secondary" onClick={() => act(() => api.post(`/api/users/${detail.id}/reset-password`, {}), 'Mot de passe temporaire généré (visible une seule fois).')}>Réinitialiser l’accès</Button> : null}
          {canDelete ? <Button variant="danger" onClick={() => act(() => api.del(`/api/users/${detail.id}`), 'Utilisateur supprimé logiquement.')}>Supprimer</Button> : null}
          <Button variant="ghost" onClick={onClose}>Fermer</Button>
        </>
      }
    >
      <div className="kv">
        <span>E-mail</span>
        <code>{detail.email}</code>
        <span>Identifiant</span>
        <code>{detail.username}</code>
        <span>Statut</span>
        <Badge tone={STATUS_TONE[detail.status] ?? 'neutral'}>{detail.status}</Badge>
        <span>Mot de passe</span>
        <span>
          <Badge tone="ok">haché Argon2id</Badge> <span className="muted small">jamais stocké ni affiché en clair</span>
        </span>
        <span>Changement requis</span>
        <span>{detail.mustChangePassword ? <Badge tone="warn">oui</Badge> : <Badge tone="ok">non</Badge>}</span>
        <span>Verrouillé jusqu’à</span>
        <span>{detail.lockedUntil ? <Badge tone="danger">{detail.lockedUntil}</Badge> : <span className="muted">non</span>}</span>
        <span>Tentatives échouées</span>
        <span>{detail.failedLoginAttempts ?? 0}</span>
        <span>Dernière connexion</span>
        <span>{detail.lastLoginAt ? new Date(detail.lastLoginAt).toLocaleString('fr-FR') : 'jamais'}</span>
      </div>

      <h4>Permissions effectives</h4>
      <div className="chips chips-small">
        {(detail.permissions ?? []).map((p) => (
          <Badge key={p} tone="neutral">{p}</Badge>
        ))}
      </div>

      <h4>Sessions actives</h4>
      <Table
        columns={[
          { key: 'createdAt', label: 'Ouverte le' },
          { key: 'lastSeenAt', label: 'Vue le' },
          { key: 'expiresAt', label: 'Expire le' },
          { key: 'ipHash', label: 'EMPREINTE_IP' },
        ]}
        rows={(detail.sessions ?? []).map((s, i) => ({ ...s, id: s.id ?? i }))}
        empty="Aucune session active."
      />

      {canUpdate ? (
        <>
          <h4>Rôles</h4>
          <div className="chips">
            {['ADMIN', 'USER'].map((r) => (
              <label key={r} className={`chip${roles.includes(r) ? ' on' : ''}`}>
                <input type="checkbox" checked={roles.includes(r)} onChange={(e) => setRoles(e.target.checked ? [...roles, r] : roles.filter((x) => x !== r))} />
                {r}
              </label>
            ))}
          </div>
          <Field label="Motif (journal d’audit)">
            <Input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={200} placeholder="ex. habilitation audit interne" />
          </Field>
          <Button
            onClick={() =>
              act(async () => {
                await api.patch(`/api/users/${detail.id}`, { roles });
                await reload(true);
              }, 'Rôles mis à jour — sessions de l’utilisateur révoquées.')
            }
            disabled={!roles.length}
          >
            Appliquer les rôles
          </Button>
        </>
      ) : null}
    </Modal>
  );
}
