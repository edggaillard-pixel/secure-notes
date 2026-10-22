import { useEffect, useRef, useState } from "react";
import { api, errorMessage } from "../api.js";
import SharePanel from "./SharePanel.jsx";

// Indicatif pour l'utilisateur uniquement : la vraie vérification
// (type MIME détecté sur le contenu) est faite par le serveur.
const ACCEPT = ".pdf,.png,.jpg,.jpeg,.webp,.gif,.txt,.md,.csv,.log";
const PERM_LABEL = { owner: "propriétaire", write: "écriture", read: "lecture" };

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} o`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} Ko`;
  return `${(bytes / 1024 / 1024).toFixed(1)} Mo`;
}

export default function FilesView() {
  const [lists, setLists] = useState({ owned: [], shared: [] });
  const [sharing, setSharing] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const inputRef = useRef(null);

  async function refresh() {
    try {
      setLists(await api.listFiles());
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function run(action) {
    setError("");
    setBusy(true);
    try {
      await action();
      await refresh();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  function upload(e) {
    e.preventDefault();
    const file = inputRef.current?.files?.[0];
    if (!file) return;
    run(async () => {
      await api.uploadFile(file);
      inputRef.current.value = "";
    });
  }

  function replace(id, file) {
    if (file) run(() => api.replaceFile(id, file));
  }

  function remove(id) {
    if (!window.confirm("Supprimer définitivement ce fichier ?")) return;
    run(async () => {
      await api.deleteFile(id);
      if (sharing === id) setSharing(null);
    });
  }

  return (
    <div className="stack">
      <form className="card row upload" onSubmit={upload}>
        <input ref={inputRef} type="file" accept={ACCEPT} required />
        <button className="primary" disabled={busy}>{busy ? "Envoi…" : "Téléverser"}</button>
        <span className="muted small">PDF, images, texte · 10 Mo max · chiffré au repos</span>
      </form>
      {error && <p className="error" role="alert">{error}</p>}

      <FileTable heading="Mes fichiers" files={lists.owned}
                 onShare={(id) => setSharing(sharing === id ? null : id)}
                 onReplace={replace} onDelete={remove} sharing={sharing} />
      <FileTable heading="Partagés avec moi" files={lists.shared} onReplace={replace} showOwner />
    </div>
  );
}

function FileTable({ heading, files, onShare, onReplace, onDelete, sharing, showOwner }) {
  return (
    <section className="card">
      <h3>{heading}</h3>
      {files.length === 0 ? (
        <p className="muted small">Aucun fichier.</p>
      ) : (
        <ul className="file-list">
          {files.map((f) => (
            <li key={f.id}>
              <div className="file-row">
                <div className="file-info">
                  <span className="item-title">{f.name}</span>
                  <span className="muted small">
                    {f.mime_type} · {formatSize(f.size)}
                    {showOwner && ` · de ${f.owner} · ${PERM_LABEL[f.permission]}`}
                  </span>
                </div>
                <div className="row">
                  {/* Navigation same-origin : cookie envoyé, réponse en « attachment ». */}
                  <a className="button" href={api.downloadUrl(f.id)} rel="noopener noreferrer">Télécharger</a>
                  {f.permission !== "read" && (
                    <label className="button">
                      Remplacer
                      <input type="file" accept={ACCEPT} hidden
                             onChange={(e) => onReplace(f.id, e.target.files?.[0])} />
                    </label>
                  )}
                  {f.permission === "owner" && (
                    <>
                      <button onClick={() => onShare(f.id)}>Partager</button>
                      <button className="danger" onClick={() => onDelete(f.id)}>Supprimer</button>
                    </>
                  )}
                </div>
              </div>
              {sharing === f.id && <SharePanel kind="files" resourceId={f.id} />}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
// GROGNON
