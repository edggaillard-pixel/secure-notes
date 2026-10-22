import { useEffect, useState } from "react";
import { api, errorMessage } from "../api.js";
import SharePanel from "./SharePanel.jsx";

const PERM_LABEL = { owner: "propriétaire", write: "écriture", read: "lecture" };

export default function NotesView() {
  const [lists, setLists] = useState({ owned: [], shared: [] });
  const [current, setCurrent] = useState(null); // note complète ou {draft:true}
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");

  async function refresh() {
    try {
      setLists(await api.listNotes());
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  function edit(note) {
    setCurrent(note);
    setTitle(note.title ?? "");
    setContent(note.content ?? "");
    setStatus("");
    setError("");
  }

  async function open(id) {
    try {
      edit(await api.getNote(id));
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function save(e) {
    e.preventDefault();
    setError("");
    try {
      const saved = current.draft
        ? await api.createNote(title, content)
        : await api.updateNote(current.id, title, content);
      edit(saved);
      setStatus("Enregistré et chiffré.");
      refresh();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function remove() {
    if (!window.confirm("Supprimer définitivement cette note ?")) return;
    try {
      await api.deleteNote(current.id);
      setCurrent(null);
      refresh();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  const canWrite = current && (current.draft || current.permission !== "read");
  const isOwner = current && !current.draft && current.permission === "owner";

  return (
    <div className="split">
      <aside className="card list-pane">
        <button className="primary block" onClick={() => edit({ draft: true, permission: "owner" })}>
          + Nouvelle note
        </button>
        <NoteList heading="Mes notes" notes={lists.owned} activeId={current?.id} onOpen={open} />
        <NoteList heading="Partagées avec moi" notes={lists.shared} activeId={current?.id} onOpen={open} showOwner />
      </aside>

      <section className="card editor-pane">
        {!current ? (
          <p className="muted">Sélectionnez une note ou créez-en une.</p>
        ) : (
          <>
            <form onSubmit={save} className="editor">
              <div className="editor-head">
                <input className="title-input" value={title} maxLength={200} required
                       readOnly={!canWrite} onChange={(e) => setTitle(e.target.value)} placeholder="Titre" />
                {!current.draft && (
                  <span className={`badge ${current.permission}`}>{PERM_LABEL[current.permission]}</span>
                )}
              </div>
              {!current.draft && current.permission !== "owner" && (
                <p className="muted small">Partagée par {current.owner}</p>
              )}
              {/* Contenu rendu comme du texte brut : jamais interprété comme du HTML. */}
              <textarea value={content} maxLength={100000} readOnly={!canWrite}
                        onChange={(e) => setContent(e.target.value)} placeholder="Contenu…" />
              <div className="row">
                {canWrite && <button className="primary">Enregistrer</button>}
                {isOwner && <button type="button" className="danger" onClick={remove}>Supprimer</button>}
                {status && <span className="ok small">{status}</span>}
              </div>
              {error && <p className="error" role="alert">{error}</p>}
            </form>
            {isOwner && <SharePanel kind="notes" resourceId={current.id} />}
          </>
        )}
      </section>
    </div>
  );
}

function NoteList({ heading, notes, activeId, onOpen, showOwner }) {
  return (
    <div className="list-group">
      <h3>{heading}</h3>
      {notes.length === 0 ? (
        <p className="muted small">Aucune.</p>
      ) : (
        <ul>
          {notes.map((n) => (
            <li key={n.id}>
              <button className={n.id === activeId ? "item active" : "item"} onClick={() => onOpen(n.id)}>
                <span className="item-title">{n.title}</span>
                {showOwner && <span className="muted small">de {n.owner} · {PERM_LABEL[n.permission]}</span>}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
// GROGNON
