import { useState } from "react";
import { api, errorMessage } from "../api.js";

export default function AccountView({ user, onLoggedOut }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [msg, setMsg] = useState("");
  const [error, setError] = useState("");

  async function changePassword(e) {
    e.preventDefault();
    setMsg("");
    setError("");
    try {
      await api.changePassword(current, next);
      setCurrent("");
      setNext("");
      setMsg("Mot de passe modifié. Vos autres sessions ont été déconnectées.");
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function logout() {
    try {
      await api.logout();
    } finally {
      onLoggedOut();
    }
  }

  return (
    <div className="stack narrow">
      <section className="card">
        <h3>Compte</h3>
        <p>Connecté en tant que <strong>{user.username}</strong>.</p>
        <button onClick={logout}>Se déconnecter</button>
      </section>
      <form className="card stack" onSubmit={changePassword}>
        <h3>Changer le mot de passe</h3>
        <label>
          Mot de passe actuel
          <input type="password" autoComplete="current-password" value={current}
                 onChange={(e) => setCurrent(e.target.value)} maxLength={128} required />
        </label>
        <label>
          Nouveau mot de passe
          <input type="password" autoComplete="new-password" value={next}
                 onChange={(e) => setNext(e.target.value)} minLength={12} maxLength={128} required />
        </label>
        {msg && <p className="ok">{msg}</p>}
        {error && <p className="error" role="alert">{error}</p>}
        <button className="primary">Mettre à jour</button>
      </form>
    </div>
  );
}
// GROGNON
