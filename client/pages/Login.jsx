import { useEffect, useState } from 'react';
import { api } from '../api.js';
import { useAuth } from '../auth.jsx';
import { Button, Card, ErrorNote, Field, InfoNote, Input } from '../ui.jsx';

export default function Login() {
  const { login } = useAuth();
  const [status, setStatus] = useState(null);
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState(null);

  useEffect(() => {
    api
      .get('/api/auth/status')
      .then(setStatus)
      .catch(() => setStatus(null));
  }, []);

  const submit = async (event) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const out = await login(identifier.trim(), password);
      if (out?.mustChangePassword) setNotice('Première connexion : le changement du mot de passe initial est obligatoire.');
    } catch (err) {
      setError(err);
      setPassword('');
    } finally {
      setBusy(false);
    }
  };

  const min = status?.policy?.passwordMinLength ?? 12;

  return (
    <div className="login-shell">
      <div className="login-brand">
        <h1>
          PrinceNsamba <span>AI</span>
        </h1>
        <p className="tagline">
          Orchestrateur d’agents de développement : analyse, code, tests, audit sécurité, second avis.
        </p>
        <ul className="brand-points">
          <li>Mots de passe hachés en <strong>Argon2id</strong>, jamais en clair</li>
          <li>RBAC appliqué côté serveur (<code>ADMIN</code> / <code>USER</code>)</li>
          <li>Journal d’audit append-only, anti brute-force persistant</li>
        </ul>
      </div>

      <Card title="Connexion" subtitle="Session via cookie HttpOnly — aucun jeton n’est lisible depuis le JavaScript.">
        {notice ? <InfoNote tone="warning">{notice}</InfoNote> : null}
        <ErrorNote error={error} onDismiss={() => setError(null)} />
        <form onSubmit={submit} className="stack">
          <Field label="E-mail ou identifiant" required>
            <Input
              value={identifier}
              onChange={(e) => setIdentifier(e.target.value)}
              autoComplete="username"
              spellCheck="false"
              required
              minLength={2}
              maxLength={200}
            />
          </Field>
          <Field label="Mot de passe" required hint={status ? `Politique serveur : ${min} caractères minimum.` : undefined}>
            <Input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
              minLength={1}
              maxLength={256}
            />
          </Field>
          <Button type="submit" loading={busy} disabled={identifier.length < 2 || !password}>
            Se connecter
          </Button>
        </form>

        <footer className="login-foot">
          {status ? (
            <p className="muted small">
              CSRF&nbsp;: {status.csrfEnabled ? 'activé' : 'désactivé'} · Cookies&nbsp;: {status.sameSite}
              {status.cookieSecure ? ' + Secure' : ''} · Verrouillage après {status.policy?.loginMaxAttempts ?? '—'} échecs · Session{' '}
              {status.policy?.sessionTtlMinutes ?? '—'} min
            </p>
          ) : (
            <p className="muted small">API indisponible — vérifiez que le serveur tourne (<code>npm start</code>).</p>
          )}
          {!status?.policy?.selfRegistration ? (
            <p className="muted small">
              La création de compte n’est pas ouverte&nbsp;: un administrateur crée les utilisateurs (principe du moindre privilège).
            </p>
          ) : null}
        </footer>
      </Card>
    </div>
  );
}

/** Forced first-login password change (server blocks every other API). */
export function ForcePasswordChange() {
  const { reload, logout, user } = useAuth();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [policy, setPolicy] = useState({ passwordMinLength: 12 });

  useEffect(() => {
    api.get('/api/auth/status').then((s) => setPolicy(s?.policy ?? {})).catch(() => {});
  }, []);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.post('/api/auth/change-password', { currentPassword: current, newPassword: next, confirm });
      await reload();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const min = policy.passwordMinLength ?? 12;
  const score = Math.min(4, Math.max(0, Math.floor((next.length - min) / 4) + (/[A-Z]/.test(next) ? 1 : 0) + (/[^A-Za-z0-9]/.test(next) ? 1 : 0)));

  return (
    <div className="login-shell">
      <Card title="Changement du mot de passe initial" subtitle={`Compte ${user?.email ?? ''} — le mot de passe temporaire ne doit pas rester en usage.`}>
        <ErrorNote error={error} onDismiss={() => setError(null)} />
        <form onSubmit={submit} className="stack">
          <Field label="Mot de passe actuel" required>
            <Input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" required />
          </Field>
          <Field label="Nouveau mot de passe" required hint={`Au moins ${min} caractères, 3 classes de caractères, ni e-mail ni identifiant.`}>
            <Input type="password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" required minLength={min} />
            <div className="strength" aria-hidden="true">
              {[0, 1, 2, 3].map((i) => (
                <span key={i} className={i < score ? 'on' : ''} />
              ))}
            </div>
          </Field>
          <Field label="Confirmation" required>
            <Input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" required minLength={min} />
          </Field>
          <div className="row">
            <Button type="submit" loading={busy} disabled={next !== confirm || next.length < min}>
              Enregistrer
            </Button>
            <Button variant="ghost" onClick={logout}>
              Se déconnecter
            </Button>
          </div>
        </form>
      </Card>
    </div>
  );
}
