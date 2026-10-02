import { useEffect, useState } from 'react';
import { api } from '../api.js';
import { useAuth } from '../auth.jsx';
import { Badge, Button, Card, ErrorNote, Field, InfoNote, Input, Table, Toolbar, useLoader } from '../ui.jsx';

export default function Profile() {
  const { user, permissions, logout, reload } = useAuth();
  const detail = useLoader(() => api.get('/api/me'), []);
  const events = useLoader(() => api.get('/api/me/events?limit=15'), []);
  const [form, setForm] = useState({ displayName: '', email: '', username: '' });
  const [pwd, setPwd] = useState({ currentPassword: '', newPassword: '', confirm: '' });
  const [error, setError] = useState(null);
  const [saved, setSaved] = useState(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (detail.data?.user) {
      setForm({ displayName: detail.data.user.displayName ?? '', email: detail.data.user.email, username: detail.data.user.username });
    }
  }, [detail.data]);

  const saveProfile = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setSaved(null);
    try {
      await api.patch('/api/me', form);
      await detail.reload(true);
      await reload();
      setSaved('Profil mis à jour.');
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const changePassword = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setSaved(null);
    try {
      await api.post('/api/auth/change-password', pwd);
      setPwd({ currentPassword: '', newPassword: '', confirm: '' });
      setSaved('Mot de passe changé. Les autres sessions ont été révoquées.');
      await events.reload(true);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const sec = detail.data?.security;

  return (
    <>
      <div className="grid-2">
        <Card title="Identité" subtitle="Ces informations sont stockées côté serveur ; le mot de passe ne transitent jamais en clair.">
          <ErrorNote error={error ?? detail.error} onDismiss={() => setError(null)} />
          {saved ? <InfoNote tone="ok">{saved}</InfoNote> : null}
          <form className="stack" onSubmit={saveProfile}>
            <Field label="Nom affiché">
              <Input value={form.displayName} onChange={(e) => setForm({ ...form, displayName: e.target.value })} maxLength={120} />
            </Field>
            <Field label="E-mail" hint="Doit rester unique ; utilisé pour l’authentification.">
              <Input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} required />
            </Field>
            <Field label="Identifiant">
              <Input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required pattern="[A-Za-z0-9][A-Za-z0-9._-]{1,31}" />
            </Field>
            <Button type="submit" loading={busy}>
              Enregistrer le profil
            </Button>
          </form>

          <h4>Rôles et permissions</h4>
          <Toolbar>
            {(detail.data?.roles ?? []).map((r) => (
              <Badge key={r} tone={r === 'ADMIN' ? 'danger' : 'neutral'}>
                rôle {r}
              </Badge>
            ))}
          </Toolbar>
          <div className="chips chips-small">
            {(permissions ?? []).map((p) => (
              <Badge key={p} tone="neutral">
                {p}
              </Badge>
            ))}
          </div>
        </Card>

        <div className="stack">
          <Card title="Mot de passe" subtitle="Argon2id, politique appliquée par le serveur (longueur, classes, dictionnaire).">
            <form className="stack" onSubmit={changePassword}>
              <Field label="Mot de passe actuel" required>
                <Input type="password" autoComplete="current-password" value={pwd.currentPassword} onChange={(e) => setPwd({ ...pwd, currentPassword: e.target.value })} required />
              </Field>
              <Field label="Nouveau mot de passe" required hint={`Minimum ${sec?.policy?.minLength ?? 12} caractères.`}>
                <Input type="password" autoComplete="new-password" value={pwd.newPassword} onChange={(e) => setPwd({ ...pwd, newPassword: e.target.value })} required minLength={sec?.policy?.minLength ?? 12} />
              </Field>
              <Field label="Confirmation" required>
                <Input type="password" autoComplete="new-password" value={pwd.confirm} onChange={(e) => setPwd({ ...pwd, confirm: e.target.value })} required />
              </Field>
              <Button type="submit" disabled={!pwd.currentPassword || !pwd.newPassword || pwd.newPassword !== pwd.confirm} loading={busy}>
                Changer le mot de passe
              </Button>
            </form>
          </Card>

          <Card dense title="État du compte">
            <div className="kv">
              <span>Dernière connexion</span>
              <span>{sec?.lastLoginAt ? new Date(sec.lastLoginAt).toLocaleString('fr-FR') : '—'}</span>
              <span>Mot de passe changé</span>
              <span>{sec?.passwordChangedAt ? new Date(sec.passwordChangedAt).toLocaleString('fr-FR') : 'jamais'}</span>
              <span>Sessions actives</span>
              <span>{sec?.sessionsActive ?? '—'}</span>
              <span>Tentatives échouées</span>
              <span>{sec?.failedLoginAttempts ?? 0}</span>
              <span>Verrouillage</span>
              <span>{sec?.lockedUntil ? <Badge tone="danger">{sec.lockedUntil}</Badge> : <Badge tone="ok">aucun</Badge>}</span>
            </div>
            <Button variant="ghost" onClick={logout}>
              Se déconnecter de cet appareil
            </Button>
          </Card>
        </div>
      </div>

      <Card dense title="Mes événements récents" subtitle="Extrait du journal d’audit vous concernant.">
        <Table
          columns={[
            { key: 'occurredAt', label: 'Quand', width: '180px' },
            { key: 'action', label: 'Action', render: (r) => <code>{r.action}</code> },
            { key: 'outcome', label: 'Résultat', width: '110px', render: (r) => <Badge tone={r.outcome === 'success' ? 'ok' : 'warn'}>{r.outcome}</Badge> },
            { key: 'severity', label: 'Sévérité', width: '110px' },
          ]}
          rows={events.data?.items ?? []}
          empty="Aucun événement."
        />
      </Card>
    </>
  );
}
