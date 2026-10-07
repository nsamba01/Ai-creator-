import { useState } from 'react';
import { api } from '../api.js';
import { useAuth } from '../auth.jsx';
import { Badge, Button, Card, ErrorNote, Field, InfoNote, Input, Modal, Table, Tabs, Toolbar, useLoader } from '../ui.jsx';

export default function Roles() {
  const { can } = useAuth();
  const roles = useLoader(() => api.get('/api/roles'), []);
  const perms = useLoader(() => api.get('/api/permissions'), []);
  const [editing, setEditing] = useState(null);
  const [creating, setCreating] = useState(false);
  const [tab, setTab] = useState('matrix');

  const canUpdate = can('roles:update');
  const list = roles.data?.roles ?? [];
  const permissions = perms.data?.permissions ?? [];

  return (
    <>
      <Card
        title="Rôles et permissions"
        subtitle="Matrice ADMIN / USER. Modifier une matrice révoque les sessions concernées : le serveur est la seule autorité."
        actions={<Button onClick={() => setCreating(true)} disabled={!can('roles:create')}>Nouveau rôle</Button>}
      >
        <ErrorNote error={roles.error ?? perms.error} />
        <Tabs
          active={tab}
          onChange={setTab}
          tabs={[
            { id: 'matrix', label: 'Matrice', count: permissions.length },
            { id: 'permissions', label: 'Catalogue', count: permissions.length },
          ]}
        />

        {tab === 'matrix' ? (
          <Table
            columns={[
              { key: 'name', label: 'Rôle', render: (r) => <strong>{r.name}</strong> },
              { key: 'description', label: 'Description', render: (r) => <span className="muted small">{r.description}</span> },
              { key: 'memberCount', label: 'Membres', width: '90px', className: 'num' },
              {
                key: 'permissions',
                label: 'Permissions',
                width: '130px',
                render: (r) => <Badge tone="neutral">{r.permissions.length}</Badge>,
              },
              { key: 'isSystem', label: 'Système', width: '90px', render: (r) => (r.isSystem ? <Badge tone="warn">oui</Badge> : <Badge tone="neutral">non</Badge>) },
              {
                key: 'edit',
                label: '',
                width: '120px',
                render: (r) => (
                  <Button variant="ghost" disabled={!canUpdate} onClick={() => setEditing(r)}>
                    Modifier
                  </Button>
                ),
              },
            ]}
            rows={list}
          />
        ) : (
          <div className="perm-groups">
            {Object.entries(perms.data?.grouped ?? {}).map(([cat, items]) => (
              <div key={cat} className="perm-group">
                <h4>{cat}</h4>
                {items.map((p) => (
                  <div key={p.key} className="perm-row">
                    <code>{p.key}</code>
                    <span className="muted small">{p.description}</span>
                    {list.map((r) => (
                      <span key={r.id} className="mini-badge" title={`${r.name} : ${r.permissions.includes(p.key) ? 'accordée' : 'refusée'}`}>
                        {r.permissions.includes(p.key) ? '✔' : '✖'}
                      </span>
                    ))}
                    {p.dangerous ? <Badge tone="danger">sensible</Badge> : null}
                  </div>
                ))}
              </div>
            ))}
          </div>
        )}
      </Card>

      {editing ? (
        <RoleModal
          role={editing}
          permissions={permissions}
          roles={list}
          onClose={() => setEditing(null)}
          onSaved={async () => {
            await roles.reload(true);
            setEditing(null);
          }}
        />
      ) : null}
      {creating ? (
        <CreateRoleModal
          onClose={() => setCreating(false)}
          onCreated={async () => {
            await roles.reload(true);
            setCreating(false);
          }}
        />
      ) : null}
    </>
  );
}

function RoleModal({ role, permissions, onClose, onSaved }) {
  const [selected, setSelected] = useState(new Set(role.permissions ?? []));
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const dirty = [...selected].sort().join() !== [...(role.permissions ?? [])].sort().join();

  const toggle = (key) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.put(`/api/roles/${role.id}/permissions`, { permissions: [...selected] });
      await onSaved();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const admin = role.name === 'ADMIN';

  return (
    <Modal
      title={`Permissions du rôle ${role.name}`}
      onClose={onClose}
      footer={
        <>
          <Button onClick={save} loading={busy} disabled={!dirty}>
            Enregistrer ({selected.size})
          </Button>
          {admin ? (
            <Button variant="ghost" onClick={() => setSelected(new Set(permissions.map((p) => p.key)))}>
              Tout accorder
            </Button>
          ) : null}
          <Button variant="ghost" onClick={() => setSelected(new Set(['dashboard:read', 'files:create', 'documents:analyze', 'urls:analyze', 'agents:read']))}>
            Profil utilisateur standard
          </Button>
        </>
      }
    >
      <ErrorNote error={error} />
      <InfoNote tone="info">
        {admin
          ? 'Le rôle ADMIN doit conserver les permissions d’administration de base : le serveur refuse toute modification qui bloquerait l’accès à la console.'
          : 'Un rôle ne peut recevoir que des permissions que l’opérateur détient lui-même (anti-escalade).'}
      </InfoNote>
      <div className="perm-grid">
        {permissions.map((p) => (
          <label key={p.key} className={`perm-check${selected.has(p.key) ? ' on' : ''}`}>
            <input type="checkbox" checked={selected.has(p.key)} onChange={() => toggle(p.key)} disabled={admin && !selected.has(p.key) && false} />
            <code>{p.key}</code>
            {p.dangerous ? <Badge tone="danger">sensible</Badge> : null}
          </label>
        ))}
      </div>
    </Modal>
  );
}

function CreateRoleModal({ onClose, onCreated }) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.post('/api/roles', { name: name.toUpperCase(), description });
      await onCreated();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title="Nouveau rôle" onClose={onClose} footer={<Button onClick={submit} loading={busy}>Créer</Button>}>
      <ErrorNote error={error} />
      <form className="stack" onSubmit={submit}>
        <Field label="Nom (MAJUSCULES)" required hint="ex. AUDITEUR">
          <Input value={name} onChange={(e) => setName(e.target.value)} required pattern="[A-Z][A-Z0-9_]{1,31}" />
        </Field>
        <Field label="Description">
          <Input value={description} onChange={(e) => setDescription(e.target.value)} maxLength={300} />
        </Field>
      </form>
    </Modal>
  );
}

export function RolesSummary() {
  const { data } = useLoader(() => api.get('/api/roles'), []);
  return <Toolbar>{(data?.roles ?? []).map((r) => <Badge key={r.id}>{r.name} · {r.memberCount}</Badge>)}</Toolbar>;
}
