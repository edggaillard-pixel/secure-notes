import { useEffect, useState } from "react";
import { api, errorMessage } from "../api.js";

/** Gestion des partages d'une ressource (visible uniquement par le propriétaire). */
export default function SharePanel({ kind, resourceId }) {
  const [shares, setShares] = useState([]);
  const [username, setUsername] = useState("");
  const [permission, setPermission] = useState("read");
  const [error, setError] = useState("");

  async function refresh() {
    try {
      setShares(await api.listShares(kind, resourceId));
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  useEffect(() => {
    setError("");
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kind, resourceId]);

  async function add(e) {
    e.preventDefault();
    setError("");
    try {
      await api.share(kind, resourceId, username.trim(), permission);
      setUsername("");
      refresh();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function revoke(id) {
    try {
      await api.revokeShare(id);
      refresh();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  return (
    <section className="share-panel">
      <h3>Partage</h3>
      <form className="row" onSubmit={add}>
        <input placeholder="Identifiant" value={username} maxLength={32}
               onChange={(e) => setUsername(e.target.value)} required />
        <select value={permission} onChange={(e) => setPermission(e.target.value)}>
          <option value="read">Lecture</option>
          <option value="write">Écriture</option>
        </select>
        <button>Partager</button>
      </form>
      {error && <p className="error" role="alert">{error}</p>}
      {shares.length === 0 ? (
        <p className="muted small">Non partagé.</p>
      ) : (
        <ul className="share-list">
          {shares.map((s) => (
            <li key={s.id}>
              <span>{s.username}</span>
              <span className={`badge ${s.permission}`}>{s.permission === "write" ? "écriture" : "lecture"}</span>
              <button className="link danger" onClick={() => revoke(s.id)}>Retirer</button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
// GROGNON
