import { useState } from "react";
import { api, errorMessage } from "../api.js";

export default function AuthPage({ onAuthenticated }) {
  const [mode, setMode] = useState("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      const data = mode === "login"
        ? await api.login(username, password)
        : await api.register(username, password);
      setPassword("");
      onAuthenticated(data.user);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const isRegister = mode === "register";
  return (
    <div className="auth-wrap">
      <form className="card auth-card" onSubmit={submit}>
        <h1 className="brand-title"><span className="brand-mark" aria-hidden="true">◆</span> Secure Notes</h1>
        <p className="muted">Notes et fichiers chiffrés, partage nominatif.</p>

        <div className="segmented" role="tablist">
          <button type="button" role="tab" aria-selected={!isRegister}
                  className={!isRegister ? "active" : ""} onClick={() => setMode("login")}>Connexion</button>
          <button type="button" role="tab" aria-selected={isRegister}
                  className={isRegister ? "active" : ""} onClick={() => setMode("register")}>Inscription</button>
        </div>

        <label>
          Identifiant
          <input value={username} onChange={(e) => setUsername(e.target.value)}
                 autoComplete="username" maxLength={32} required />
        </label>
        <label>
          Mot de passe
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
                 autoComplete={isRegister ? "new-password" : "current-password"}
                 minLength={isRegister ? 12 : 1} maxLength={128} required />
        </label>
        {isRegister && (
          <p className="hint">12 caractères minimum. Une phrase de passe est idéale.</p>
        )}
        {error && <p className="error" role="alert">{error}</p>}
        <button className="primary" disabled={busy}>
          {busy ? "…" : isRegister ? "Créer le compte" : "Se connecter"}
        </button>
      </form>
    </div>
  );
}
// GROGNON
