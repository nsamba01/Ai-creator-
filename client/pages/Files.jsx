import { useRef, useState } from 'react';
import { api } from '../api.js';
import { Badge, Button, Card, ErrorNote, InfoNote, Table, Toolbar, useLoader } from '../ui.jsx';

const MAX_MB = 10;

export default function Files() {
  const inputRef = useRef(null);
  const { data, error, reload } = useLoader(() => api.get('/api/files?limit=100'), []);
  const [busy, setBusy] = useState(false);
  const [localError, setLocalError] = useState(null);
  const [info, setInfo] = useState(null);

  const upload = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    setBusy(true);
    setLocalError(null);
    setInfo(null);
    try {
      const form = new FormData();
      form.append('file', file);
      const out = await api.form('/api/files', form);
      setInfo(
        out.duplicate
          ? 'Un fichier identique (même SHA-256) appartenait déjà à ce compte : aucun octet dupliqué.'
          : `Téléversé (${(out.file.sizeBytes / 1024).toFixed(1)} Ko, sha256 ${out.file.sha256.slice(0, 12)}…).`,
      );
      await reload(true);
    } catch (err) {
      setLocalError(err);
    } finally {
      setBusy(false);
      if (inputRef.current) inputRef.current.value = '';
    }
  };

  const download = async (row) => {
    setLocalError(null);
    try {
      const res = await fetch(`/api/files/${row.id}/content`, { credentials: 'include' });
      if (!res.ok) throw new Error(`Téléchargement refusé (${res.status})`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = row.originalName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
      await reload(true);
    } catch (err) {
      setLocalError(err);
    }
  };

  return (
    <Card
      title="Fichiers"
      subtitle="Stockés hors du serveur statique, servis uniquement par l’API, en téléchargement forcé (jamés exécutés ni rendus en ligne)."
      actions={
        <Toolbar>
          <input ref={inputRef} type="file" onChange={upload} disabled={busy} aria-label="fichier à téléverser" />
          <Button loading={busy} onClick={() => inputRef.current?.click()}>
            Téléverser
          </Button>
        </Toolbar>
      }
    >
      <ErrorNote error={localError ?? error} onDismiss={() => setLocalError(null)} />
      {info ? <InfoNote tone="ok">{info}</InfoNote> : null}
      <InfoNote tone="warning">
        Contrôles appliqués : extension dans la liste autorisée, MIME cohérent, signature binaire vérifiée, taille ≤ {MAX_MB} Mo, quota personnel, nom
        de fichier remplacé par un UUID, exécution impossible. Les scripts, HTML, SVG et exécutables sont refusés.
      </InfoNote>
      <Table
        columns={[
          { key: 'id', label: '#', width: '60px', className: 'num' },
          { key: 'originalName', label: 'Nom', render: (f) => <strong>{f.originalName}</strong> },
          { key: 'kind', label: 'Type', width: '110px', render: (f) => <Badge tone="neutral">{f.kind}</Badge> },
          { key: 'sizeBytes', label: 'Taille', width: '100px', className: 'num', render: (f) => `${(f.sizeBytes / 1024).toFixed(1)} Ko` },
          {
            key: 'magicOk',
            label: 'Signature',
            width: '100px',
            render: (f) => (f.magicOk ? <Badge tone="ok">vérifiée</Badge> : <Badge tone="danger">incohérente</Badge>),
          },
          { key: 'sha256', label: 'SHA-256', width: '130px', render: (f) => <code className="small muted">{f.sha256.slice(0, 12)}…</code> },
          { key: 'downloadCount', label: 'Téléch.', width: '80px', className: 'num' },
          { key: 'ownerName', label: 'Propriétaire', width: '120px' },
          { key: 'createdAt', label: 'Ajouté le', width: '160px' },
          {
            key: 'actions',
            label: '',
            width: '150px',
            render: (f) => (
              <Toolbar>
                <Button variant="ghost" onClick={() => download(f)}>
                  Télécharger
                </Button>
                <Button
                  variant="danger"
                  onClick={async () => {
                    await api.del(`/api/files/${f.id}`).catch((e) => setLocalError(e));
                    await reload(true);
                  }}
                >
                  Supprimer
                </Button>
              </Toolbar>
            ),
          },
        ]}
        rows={data?.items ?? []}
        empty="Aucun fichier téléversé."
      />
    </Card>
  );
}
