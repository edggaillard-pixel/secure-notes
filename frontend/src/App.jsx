import { useEffect, useState } from "react";
import { api } from "./api.js";
import AuthPage from "./components/AuthPage.jsx";
import NotesView from "./components/NotesView.jsx";
import FilesView from "./components/FilesView.jsx";
import AccountView from "./components/AccountView.jsx";

/*
 * Rappel XSS : tout le contenu utilisateur est rendu via JSX ({valeur}),
 * que React échappe automatiquement. dangerouslySetInnerHTML n'est utilisé
 * nulle part dans le projet (vérifiable par grep). La CSP stricte servie
 * par Nginx est le second filet de sécurité.
 */

const TABS = [
  { id: "notes", label: "Notes" },
  { id: "files", label: "Fichiers" },
  { id: "account", label: "Compte" },
];

export default function App() {
  const [user, setUser] = useState(undefined); // undefined = chargement
  const [tab, setTab] = useState("notes");

  useEffect(() => {
    api.me().then((d) => setUser(d.user)).catch(() => setUser(null));
  }, []);

  if (user === undefined) return <div className="splash">Chargement…</div>;
  if (user === null) return <AuthPage onAuthenticated={setUser} />;

  return (
    <div className="shell">
      <header className="topbar">
        <span className="brand">
          <span className="brand-mark" aria-hidden="true">◆</span> Secure Notes
        </span>
        <nav className="tabs" aria-label="Sections">
          {TABS.map((t) => (
            <button
              key={t.id}
              className={tab === t.id ? "tab active" : "tab"}
              aria-current={tab === t.id ? "page" : undefined}
              onClick={() => setTab(t.id)}
            >
              {t.label}
            </button>
          ))}
        </nav>
        <span className="whoami">{user.username}</span>
      </header>
      <main className="content">
        {tab === "notes" && <NotesView />}
        {tab === "files" && <FilesView />}
        {tab === "account" && <AccountView user={user} onLoggedOut={() => setUser(null)} />}
      </main>
    </div>
  );
}
// GROGNON
