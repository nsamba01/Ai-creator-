import { useEffect, useState } from 'react';
import { api } from '../api.js';
import { useAuth } from '../auth.jsx';
import { Badge, Button, Card, ErrorNote, Field, InfoNote, Input, Select, Table, Toolbar } from '../ui.jsx';

export default function Settings() {
  const { can } = useAuth();
  const [data, setData] = useState(null);
  const [draft, setDraft] = useState({});
  const [error, setError] = useState(null);
  const [saved, setSaved] = useState(null);
  const [busy, setBusy] = useState(false);

  const canUpdate = can('settings:update');

  const load = async () => {
    try {
      const out = await api.get('/api/admin/settings');
      setData(out);
      setDraft(Object.fromEntries(out.settings.map((s) => [s.key, s.value])));
    } catch (err) {
      setError(err);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const dirty = Object.entries(draft).filter(([k, v]) => {
    const original = data?.settings?.find((s) => s.key === k)?.value;
    return String(original ?? '') !== String(v ?? '');
  });

  const save = async () => {
    setBusy(true);
    setError(null);
    setSaved(null);
    try {
      const payload = Object.fromEntries(dirty.map(([k, v]) => [k, coerce(data.settings.find((s) => s.key === k), v)]));
      const out = await api.put('/api/admin/settings', { entries: payload });
      setSaved(out);
      await load();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  if (error && !data) return <ErrorNote error={error} />;
  if (!data) return <p className="muted">Chargement de la configuration…</p>;

  return (
    <>
      <Card
        title="Configuration autorisée"
        subtitle="Seules les clés déclarées côté serveur sont modifiables, avec type et bornes vérifiées. Un non-administrateur ne peut pas écrire ici."
        actions={
          <Toolbar>
            <Badge tone={dirty.length ? 'warn' : 'neutral'}>{dirty.length} modification(s)</Badge>
            <Button onClick={save} disabled={!canUpdate || !dirty.length} loading={busy}>
              Enregistrer
            </Button>
          </Toolbar>
        }
      >
        {!canUpdate ? <InfoNote tone="warning">Lecture seule : la permission <code>settings:update</code> est requise pour modifier.</InfoNote> : null}
        <ErrorNote error={error} onDismiss={() => setError(null)} />
        {saved ? (
          <InfoNote tone="ok">
            {saved.updated.length} clé(s) mise(s) à jour{saved.rejected.length ? `, ${saved.rejected.length} refusée(s)` : ''}. Chaque changement est
            journalisé dans l’audit.
          </InfoNote>
        ) : null}

        <div className="settings-grid">
          {data.settings.map((s) => (
            <Field key={s.key} label={s.key} hint={`${s.description} · type ${s.type}${s.min !== undefined ? ` · min ${s.min}` : ''}${s.max !== undefined ? ` · max ${s.max}` : ''}`}>
              {s.type === 'bool' ? (
                <Select value={String(draft[s.key])} onChange={(e) => setDraft({ ...draft, [s.key]: e.target.value })} disabled={!canUpdate}>
                  <option value="true">true</option>
                  <option value="false">false</option>
                </Select>
              ) : s.masked ? (
                <Input value="[défini — lecture masquée]" readOnly />
              ) : (
                <Input
                  type={s.type === 'int' ? 'number' : 'text'}
                  value={draft[s.key] ?? ''}
                  min={s.min}
                  max={s.max}
                  disabled={!canUpdate}
                  onChange={(e) => setDraft({ ...draft, [s.key]: e.target.value })}
                />
              )}
            </Field>
          ))}
        </div>
      </Card>

      <Card dense title="Valeurs effectives" subtitle="Ce que le serveur applique réellement (le cache de configuration est court par conception).">
        <Table
          columns={[
            { key: 'k', label: 'Paramètre' },
            { key: 'v', label: 'Valeur appliquée', render: (r) => <code>{String(r.v)}</code> },
          ]}
          rows={Object.entries(data.effective ?? {}).map(([k, v], i) => ({ id: `${k}-${i}`, k, v }))}
          keyField="id"
        />
      </Card>
    </>
  );
}

function coerce(spec, value) {
  if (spec?.type === 'int') return Number.parseInt(String(value), 10);
  if (spec?.type === 'bool') return String(value) === 'true';
  return String(value);
}
