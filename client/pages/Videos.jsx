import { useRef, useState } from 'react';
import { api } from '../api.js';
import { Badge, Button, Card, ErrorNote, InfoNote, Modal, Stat, Table, Toolbar, useLoader } from '../ui.jsx';

/**
 * Agent Vidéo — phase A.
 *
 * L’écran montre ce que le serveur sait faire aujourd’hui : déclarer une vidéo déjà
 * téléversée (ou l’amener ici), lire le rapport de sondage, demander la quarantaine.
 * Aucun lecteur n’est embarqué : la lecture en continu (Range, authentifiée) est la
 * phase B, et une balise <video> pointant hors de ces routes serait une faille, pas
 * une fonctionnalité.
 */
const STATUS_TONE = { ready: 'ok', pending: 'neutral', probing: 'neutral', failed: 'danger', quarantined: 'warn' };
const STATUS_LABEL = { ready: 'prête', pending: 'en attente', probing: 'en cours', failed: 'échec', quarantined: 'quarantaine' };

function duration(ms) {
  if (!Number.isFinite(ms) || ms <= 0) return '—';
  const s = Math.round(ms / 1000);
  const m = Math.floor(s / 60);
  return m > 0 ? `${m} min ${String(s % 60).padStart(2, '0')} s` : `${s} s`;
}

function megaoctets(bytes) {
  return `${Math.round(((bytes ?? 0) / 1048576) * 10) / 10} Mo`;
}

function geometry(asset) {
  if (!asset.width || !asset.height) return '—';
  return `${asset.width}×${asset.height}${asset.fps ? ` · ${asset.fps} im/s` : ''}`;
}

export default function Videos() {
  const { data, error, reload } = useLoader(async () => {
    const [list, stats] = await Promise.all([api.get('/api/videos?limit=50'), api.get('/api/videos/stats')]);
    return { ...list, stats };
  }, []);
  const [detail, setDetail] = useState(null);
  const [fileId, setFileId] = useState('');
  const [busy, setBusy] = useState(false);
  const [localError, setLocalError] = useState(null);
  const [notice, setNotice] = useState(null);
  const inputRef = useRef(null);
  const stats_ = data?.stats;

  const run = async (action) => {
    setBusy(true);
    setLocalError(null);
    try {
      const message = await action();
      if (message) setNotice(message);
      await reload(true);
      return true;
    } catch (err) {
      setLocalError(err);
      return false;
    } finally {
      setBusy(false);
    }
  };

  const upload = (event) => {
    const file = event.target.files?.[0];
    if (!file) return Promise.resolve();
    const form = new FormData();
    form.append('file', file, file.name);
    return run(async () => {
      const out = await api.form('/api/videos/upload', form);
      if (inputRef.current) inputRef.current.value = '';
      return `${out.file.originalName} — état « ${out.asset.status} », sondage « ${out.asset.probeSource} ».`;
    }).then((ok) => {
      if (!ok && inputRef.current) inputRef.current.value = '';
    });
  };

  const declare = () => {
    const id = Number(String(fileId).trim());
    if (!Number.isInteger(id) || id <= 0) {
      setLocalError(new Error('Indiquez un identifiant de fichier entier et positif.'));
      return Promise.resolve();
    }
    return run(async () => {
      const out = await api.post('/api/videos', { fileId: id });
      setFileId('');
      return out.alreadyRegistered ? 'Cette vidéo était déjà déclarée : état rechargé.' : `Vidéo n° ${out.asset.id} déclarée et sondée.`;
    });
  };

  const open = (row) =>
    api
      .get(`/api/videos/${row.id}`)
      .then(setDetail)
      .catch((err) => setLocalError(err));

  const act = (id, action) =>
    run(async () => {
      await api.post(`/api/videos/${id}/${action}`, {});
      setDetail(await api.get(`/api/videos/${id}`));
      return action === 'probe' ? 'Sondage relancé.' : action === 'release' ? 'Quarantaine levée.' : 'Vidéo placée en quarantaine.';
    });

  const asset = detail?.asset;

  return (
    <>
      <Card title="Agent vidéo" subtitle="Phase A : déclaration, sondage des en-têtes de conteneur, quarantaine. Aucun transcodage, aucune lecture en continu.">
        <Toolbar>
          <input ref={inputRef} type="file" accept=".mp4,.m4v,.mov,.mkv,.webm,.avi" onChange={upload} disabled={busy} aria-label="fichier vidéo à téléverser" className="input" />
          <Button loading={busy} onClick={() => inputRef.current?.click()} disabled={!stats_ || !stats_.enabled}>
            Amener une vidéo
          </Button>
        </Toolbar>
        <Toolbar>
          <label className="field-label" htmlFor="video-file-id">
            Identifiant d’un fichier vidéo déjà téléversé
          </label>
          <input id="video-file-id" className="input" value={fileId} onChange={(e) => setFileId(e.target.value)} placeholder="ex. 42" inputMode="numeric" />
          <Button variant="secondary" onClick={declare} disabled={busy || !stats_ || !stats_.enabled}>
            Déclarer et sonder
          </Button>
          <Button variant="ghost" onClick={() => reload()}>
            Recharger
          </Button>
        </Toolbar>
        <ErrorNote error={error ?? localError} onDismiss={() => setLocalError(null)} />
        {notice ? <InfoNote tone="ok">{notice}</InfoNote> : null}
        {stats_ && !stats_.enabled ? (
          <InfoNote tone="warning">
            L’ingestion vidéo est éteinte. Un administrateur doit activer le réglage <code>video.enabled</code> dans Configuration pour autoriser les
            déclarations.
          </InfoNote>
        ) : null}
        {stats_ ? (
          <div className="stats">
            <Stat label="Vidéos suivies" value={stats_.count} hint={`${megaoctets(stats_.bytes)} cumules`} />
            <Stat label="En quarantaine" value={stats_.quarantined} tone={stats_.quarantined ? 'warn' : 'default'} />
            <Stat label="Durée maximale acceptée" value={`${Math.round(stats_.limits.maxDurationMs / 1000)} s`} hint="au-delà : quarantaine, jamais de lecture" />
            <Stat label="Taille maximale" value={megaoctets(Math.min(stats_.limits.maxUploadBytes, stats_.limits.maxFileBytes))} hint="plafonné par la limite globale de téléversement" />
            <Stat label="ffprobe" value={stats_.ffprobeConfigured ? 'configuré' : 'indisponible'} hint={stats_.ffprobeConfigured ? 'complète le sondage JS s’il répond' : 'sondage sur en-têtes uniquement'} />
          </div>
        ) : null}
        <Table
          caption="Rapports produits par le serveur"
          columns={[
            { key: 'fileName', label: 'fichier' },
            { key: 'container', label: 'conteneur' },
            { key: 'codec', label: 'codec' },
            { key: 'durationMs', label: 'durée', render: (r) => duration(r.durationMs) },
            { key: 'geometry', label: 'images', render: (r) => geometry(r) },
            { key: 'sizeBytes', label: 'taille', render: (r) => megaoctets(r.sizeBytes), className: 'num' },
            { key: 'probeSource', label: 'source', render: (r) => <Badge tone="neutral">{r.probeSource}</Badge> },
            { key: 'status', label: 'état', render: (r) => <Badge tone={STATUS_TONE[r.status] ?? 'neutral'}>{STATUS_LABEL[r.status] ?? r.status}</Badge> },
          ]}
          rows={data?.items ?? []}
          empty="Aucune vidéo déclarée. Déposez un MP4, MOV, M4V, MKV, WebM ou AVI réel : la signature du conteneur est vérifiée avant tout traitement."
          onRowClick={open}
        />
        <p className="muted small">
          Un simple renommage (.png → .mp4) est rejeté : la signature du fichier commande, pas son nom. Les valeurs affichées sont déclaratives — elles
          viennent de l’en-tête du conteneur, pas d’une analyse des images. Lecture en continu, montage, vignettes et sous-titres : phase B.
        </p>
      </Card>

      {asset ? (
        <Modal title={detail.file?.name ?? 'Rapport de sondage'} onClose={() => setDetail(null)}>
          <div className="row">
            <Badge tone={STATUS_TONE[asset.status] ?? 'neutral'}>{STATUS_LABEL[asset.status] ?? asset.status}</Badge>
            {asset.errorCode ? <Badge tone="danger">{asset.errorCode}</Badge> : null}
          </div>
          <div className="kv">
            <span>Conteneur</span>
            <code>{asset.container ?? '—'}</code>
            <span>Marque</span>
            <code>{asset.brand ?? '—'}</code>
            <span>Codec vidéo</span>
            <code>{asset.codec ?? '—'}</code>
            <span>Durée</span>
            <span>{duration(asset.durationMs)}</span>
            <span>Images</span>
            <span>{geometry(asset)}</span>
            <span>Débit annoncé</span>
            <span>{asset.bitrateBps ? `${Math.round(asset.bitrateBps / 1000)} kbit/s` : '—'}</span>
            <span>Pistes</span>
            <span>{asset.trackCount ?? 0}</span>
            <span>Taille</span>
            <span>{megaoctets(asset.sizeBytes)}</span>
            <span>Sondé par</span>
            <span>
              {asset.parser ?? '—'} · source <code>{asset.probeSource}</code>
            </span>
            <span>Empreinte (tronquée)</span>
            <code>{asset.sha256 ?? '—'}</code>
            <span>Déclarée le</span>
            <span>{asset.createdAt}</span>
          </div>
          {asset.notes?.length ? (
            <ul className="findings">
              {asset.notes.map((note, i) => (
                <li key={i} className="finding finding-info">
                  <span>{note}</span>
                </li>
              ))}
            </ul>
          ) : null}
          {asset.file?.mime ? (
            <p className="muted small">
              Type déclaré côté serveur : <code>{asset.file.mime}</code>. Le nom de stockage n’est jamais exposé.
            </p>
          ) : null}
          <div className="card-actions">
            <Button variant="secondary" loading={busy} onClick={() => act(asset.id, 'probe')}>
              Relancer le sondage
            </Button>
            {asset.status === 'quarantined' ? (
              <Button variant="danger" loading={busy} onClick={() => act(asset.id, 'release')}>
                Lever la quarantaine
              </Button>
            ) : (
              <Button variant="ghost" loading={busy} onClick={() => act(asset.id, 'quarantine')}>
                Mettre en quarantaine
              </Button>
            )}
          </div>
          <p className="muted small">
            Ces actions sont refusées sans la permission <code>videos:process</code> côté serveur — l’interface ne décide jamais.
          </p>
        </Modal>
      ) : null}
    </>
  );
}
