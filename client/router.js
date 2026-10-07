/** Hash-based router (no dependency). Routes look like #/users?status=active. */
import { useCallback, useEffect, useState } from 'react';

function parse(hash) {
  const raw = String(hash ?? '').replace(/^#/, '') || '/';
  const [pathPart, queryPart] = raw.split('?');
  const path = pathPart.startsWith('/') ? pathPart : `/${pathPart}`;
  const query = Object.fromEntries(new URLSearchParams(queryPart ?? ''));
  return { path, query };
}

export function useRoute() {
  const [route, setRoute] = useState(() => parse(window.location.hash));

  useEffect(() => {
    const onHash = () => setRoute(parse(window.location.hash));
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  const navigate = useCallback((to, { replace = false } = {}) => {
    const target = `#${to.startsWith('/') ? to : `/${to}`}`;
    if (replace) window.location.replace(target);
    else window.location.hash = target;
    setRoute(parse(target));
  }, []);

  return { ...route, navigate };
}
