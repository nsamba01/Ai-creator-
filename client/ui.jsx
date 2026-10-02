/** Shared UI primitives + tiny data hook. Deliberately dependency-free. */
import { useCallback, useEffect, useRef, useState } from 'react';
import { api, qs } from './api.js';

export function Card({ title, subtitle, actions, children, tone = 'default', dense = false }) {
  return (
    <section className={`card tone-${tone}${dense ? ' dense' : ''}`}>
      {(title || actions) && (
        <header className="card-head">
          <div>
            {title && <h2>{title}</h2>}
            {subtitle && <p className="muted">{subtitle}</p>}
          </div>
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      <div className="card-body">{children}</div>
    </section>
  );
}

export function Button({ children, variant = 'primary', type = 'button', loading, disabled, ...rest }) {
  return (
    <button type={type} className={`btn btn-${variant}`} disabled={disabled || loading} {...rest}>
      {loading ? <span className="spinner" aria-hidden="true" /> : null}
      {children}
    </button>
  );
}

export function Field({ label, hint, error, children, required }) {
  return (
    <label className="field">
      <span className="field-label">
        {label}
        {required ? <em className="req" title="obligatoire">*</em> : null}
      </span>
      {children}
      {hint && !error ? <small className="muted">{hint}</small> : null}
      {error ? <small className="error">{error}</small> : null}
    </label>
  );
}

export function Input({ ...rest }) {
  return <input className="input" {...rest} />;
}

export function Textarea({ ...rest }) {
  return <textarea className="input textarea" rows={4} {...rest} />;
}

export function Select({ children, ...rest }) {
  return <select className="input select" {...rest}>{children}</select>;
}

export function Badge({ children, tone = 'neutral', title }) {
  return (
    <span className={`badge badge-${tone}`} title={title}>
      {children}
    </span>
  );
}

export function StatusDot({ ok, label }) {
  return (
    <span className={`dot ${ok ? 'ok' : 'ko'}`} title={ok ? 'satisfait' : 'à corriger'}>
      {label}
    </span>
  );
}

export function Table({ columns, rows, empty = 'Aucune donnée.', keyField = 'id', onRowClick, caption }) {
  if (!rows?.length) return <p className="muted empty">{empty}</p>;
  return (
    <div className="table-wrap">
      <table>
        {caption ? <caption>{caption}</caption> : null}
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} scope="col" style={c.width ? { width: c.width } : undefined}>
                {c.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr
              key={row[keyField] ?? i}
              className={onRowClick ? 'clickable' : undefined}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
            >
              {columns.map((c) => (
                <td key={c.key} className={c.className}>
                  {c.render ? c.render(row, i) : formatCell(row[c.key])}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function formatCell(value) {
  if (value === null || value === undefined || value === '') return <span className="muted">—</span>;
  if (typeof value === 'boolean') return value ? 'oui' : 'non';
  if (typeof value === 'number') return value.toLocaleString('fr-FR');
  return String(value);
}

export function ErrorNote({ error, onDismiss }) {
  if (!error) return null;
  const details = error.details?.reasons ?? error.details?.missing ?? error.details?.blocked;
  return (
    <div className="note note-error" role="alert">
      <div>
        <strong>{error.code ?? 'Erreur'}</strong> — {error.message}
        {Array.isArray(details) && details.length ? <ul>{details.map((d) => <li key={String(d)}>{String(d)}</li>)}</ul> : null}
        {error.requestId ? <small className="muted"> (requestId {error.requestId})</small> : null}
      </div>
      {onDismiss ? <button className="link" onClick={onDismiss}>masquer</button> : null}
    </div>
  );
}

export function InfoNote({ tone = 'info', children }) {
  return <div className={`note note-${tone}`}>{children}</div>;
}

export function Stat({ label, value, hint, tone = 'default' }) {
  return (
    <div className={`stat stat-${tone}`}>
      <span className="stat-value">{value}</span>
      <span className="stat-label">{label}</span>
      {hint ? <span className="stat-hint muted">{hint}</span> : null}
    </div>
  );
}

export function Toolbar({ children }) {
  return <div className="toolbar">{children}</div>;
}

export function Modal({ title, children, onClose, footer }) {
  const ref = useRef(null);
  useEffect(() => {
    const onKey = (e) => e.key === 'Escape' && onClose?.();
    document.addEventListener('keydown', onKey);
    ref.current?.focus();
    return () => document.removeEventListener('keydown', onKey);
  }, [onClose]);
  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose?.()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title} tabIndex={-1} ref={ref}>
        <header>
          <h3>{title}</h3>
          <button className="link" onClick={onClose} aria-label="Fermer">✕</button>
        </header>
        <div className="modal-body">{children}</div>
        {footer ? <footer className="modal-foot">{footer}</footer> : null}
      </div>
    </div>
  );
}

export function Tabs({ tabs, active, onChange }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button
          key={t.id}
          role="tab"
          aria-selected={active === t.id}
          className={`tab${active === t.id ? ' active' : ''}`}
          onClick={() => onChange(t.id)}
        >
          {t.label}
          {t.count !== undefined ? <span className="tab-count">{t.count}</span> : null}
        </button>
      ))}
    </div>
  );
}

/** Fetch-on-mount hook with manual reload, loading and error states. */
export function useLoader(fn, deps = []) {
  const [state, setState] = useState({ data: null, loading: true, error: null });
  const mounted = useRef(true);
  const run = useCallback(
    async (silent = false) => {
      if (!silent) setState((s) => ({ ...s, loading: true }));
      try {
        const data = await fn();
        if (mounted.current) setState({ data, loading: false, error: null });
        return data;
      } catch (error) {
        if (mounted.current) setState((s) => ({ ...s, loading: false, error }));
        return null;
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    deps,
  );
  useEffect(() => {
    mounted.current = true;
    run();
    return () => {
      mounted.current = false;
    };
  }, [run]);
  return { ...state, reload: run, setData: (data) => setState((s) => ({ ...s, data })) };
}

/** Debounced value for search inputs. */
export function useDebounced(value, delay = 350) {
  const [v, setV] = useState(value);
  useEffect(() => {
    const id = setTimeout(() => setV(value), delay);
    return () => clearTimeout(id);
  }, [value, delay]);
  return v;
}

export { qs };
