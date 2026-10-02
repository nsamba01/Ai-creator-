import { useEffect, useState } from 'react';
import { useAuth } from './auth.jsx';
import { useRoute } from './router.js';
import Login, { ForcePasswordChange } from './pages/Login.jsx';
import Dashboard from './pages/Dashboard.jsx';
import Users from './pages/Users.jsx';
import Roles from './pages/Roles.jsx';
import Sessions from './pages/Sessions.jsx';
import Audit from './pages/Audit.jsx';
import Files from './pages/Files.jsx';
import Documents from './pages/Documents.jsx';
import Urls from './pages/Urls.jsx';
import Agents from './pages/Agents.jsx';
import Settings from './pages/Settings.jsx';
import Security from './pages/Security.jsx';
import Profile from './pages/Profile.jsx';
import { Badge } from './ui.jsx';

const NAV = [
  { id: '/', label: 'Tableau de bord', icon: '◲', component: Dashboard, public: true },
  { id: '/users', label: 'Utilisateurs', icon: '👤', component: Users, permission: 'users:read' },
  { id: '/roles', label: 'Rôles & permissions', icon: '⚿', component: Roles, permission: 'roles:read' },
  { id: '/sessions', label: 'Sessions', icon: '⏻', component: Sessions },
  { id: '/audit', label: 'Journal d’audit', icon: '≣', component: Audit, permission: 'audit:read' },
  { id: '/files', label: 'Fichiers', icon: '⎘', component: Files },
  { id: '/documents', label: 'Documents', icon: '❐', component: Documents, permission: 'documents:analyze' },
  { id: '/urls', label: 'Analyse d’URL', icon: '⌁', component: Urls, permission: 'urls:analyze' },
  { id: '/agents', label: 'Agents IA', icon: '⟟', component: Agents, permission: 'agents:read' },
  { id: '/security', label: 'Sécurité', icon: '⛨', component: Security },
  { id: '/settings', label: 'Configuration', icon: '⚙', component: Settings, permission: 'settings:read' },
  { id: '/profile', label: 'Mon compte', icon: '☺', component: Profile },
];

export default function App() {
  const { status, user, can, isAdmin, mustChangePassword, logout } = useAuth();
  const { path, navigate } = useRoute();
  const [menuOpen, setMenuOpen] = useState(false);
  const [toast, setToast] = useState(null);

  useEffect(() => {
    const onToast = (e) => {
      setToast(e.detail);
      setTimeout(() => setToast(null), 4200);
    };
    const onUnauthorized = () => navigate('/login', { replace: true });
    window.addEventListener('princesamba:toast', onToast);
    window.addEventListener('princesamba:unauthorized', onUnauthorized);
    return () => {
      window.removeEventListener('princesamba:toast', onToast);
      window.removeEventListener('princesamba:unauthorized', onUnauthorized);
    };
  }, [navigate]);

  useEffect(() => {
    if (status === 'anonymous' && path !== '/login') navigate('/login', { replace: true });
    if (status === 'ready' && path === '/login') navigate('/', { replace: true });
  }, [status, path, navigate]);

  if (status === 'loading') {
    return (
      <div className="boot">
        <span className="spinner" /> Vérification de la session…
      </div>
    );
  }

  if (status === 'anonymous' || path === '/login') return <Login />;
  if (mustChangePassword) return <ForcePasswordChange />;

  const visible = NAV.filter((item) => !item.permission || can(item.permission));
  const current = visible.find((item) => item.id === path) ?? visible[0];
  const Page = current.component;

  return (
    <div className="shell">
      <aside className={`sidebar${menuOpen ? ' open' : ''}`}>
        <div className="brand">
          <span className="brand-mark">P</span>
          <div>
            <strong>PrinceNsamba AI</strong>
            <small>console d’ingénierie</small>
          </div>
        </div>
        <nav>
          {visible.map((item) => (
            <a
              key={item.id}
              href={`#${item.id}`}
              className={current.id === item.id ? 'active' : ''}
              onClick={() => setMenuOpen(false)}
            >
              <span className="nav-icon" aria-hidden="true">
                {item.icon}
              </span>
              {item.label}
            </a>
          ))}
        </nav>
        <footer className="sidebar-foot">
          <Badge tone={isAdmin ? 'danger' : 'neutral'}>{isAdmin ? 'ADMIN' : 'USER'}</Badge>
          <span className="muted small">{user?.email}</span>
        </footer>
      </aside>

      <main className="content">
        <header className="topbar">
          <button className="burger" onClick={() => setMenuOpen((v) => !v)} aria-label="Menu">
            ☰
          </button>
          <h1>{current.label}</h1>
          <div className="topbar-actions">
            <span className="muted small">{user?.displayName || user?.username}</span>
            <button className="link" onClick={logout}>
              Déconnexion
            </button>
          </div>
        </header>
        <div className="page">
          <Page />
        </div>
      </main>

      {toast ? <div className="toast">{toast}</div> : null}
    </div>
  );
}
