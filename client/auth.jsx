/**
 * Auth store: the SPA holds *profile* data only (id, roles, permissions) —
 * never a token. Authentication lives in HttpOnly cookies.
 */
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { api, primeCsrfToken } from './api.js';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [state, setState] = useState({ status: 'loading', user: null, permissions: [], mustChangePassword: false, error: null });

  const loadMe = useCallback(async () => {
    try {
      const me = await api.get('/api/auth/me');
      setState({
        status: 'ready',
        user: me.user,
        permissions: me.permissions ?? [],
        mustChangePassword: Boolean(me.mustChangePassword),
        error: null,
      });
      return me;
    } catch (err) {
      setState({ status: 'anonymous', user: null, permissions: [], mustChangePassword: false, error: null });
      return null;
    }
  }, []);

  useEffect(() => {
    loadMe();
    const onForced = () => setState((s) => (s.mustChangePassword ? s : { ...s, mustChangePassword: true }));
    const onRefreshed = () => loadMe();
    window.addEventListener('princesamba:force-password', onForced);
    window.addEventListener('princesamba:session-refreshed', onRefreshed);
    return () => {
      window.removeEventListener('princesamba:force-password', onForced);
      window.removeEventListener('princesamba:session-refreshed', onRefreshed);
    };
  }, [loadMe]);

  const login = useCallback(
    async (identifier, password) => {
      const out = await api.post('/api/auth/login', { identifier, password });
      if (out?.csrfToken) primeCsrfToken(out.csrfToken);
      setState({
        status: 'ready',
        user: out.user,
        permissions: out.user?.permissions ?? [],
        mustChangePassword: Boolean(out.mustChangePassword),
        error: null,
      });
      return out;
    },
    [],
  );

  const logout = useCallback(async () => {
    try {
      await api.post('/api/auth/logout', {});
    } finally {
      primeCsrfToken(null);
      setState({ status: 'anonymous', user: null, permissions: [], mustChangePassword: false, error: null });
    }
  }, []);

  const value = useMemo(
    () => ({
      ...state,
      login,
      logout,
      reload: loadMe,
      can: (permission) => (permission ? state.permissions.includes(permission) : true),
      isAdmin: state.user?.roles?.includes('ADMIN') ?? false,
    }),
    [state, login, logout, loadMe],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth doit être utilisé dans <AuthProvider>');
  return ctx;
}
