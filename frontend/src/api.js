/**
 * Client HTTP de l'API.
 *
 * - Même origine que l'API (Nginx proxifie /api) : aucun CORS à ouvrir,
 *   et le cookie SameSite=Strict est envoyé normalement.
 * - Le cookie de session est HttpOnly : ce code n'y a JAMAIS accès.
 *   Seul le jeton CSRF (non sensible seul) est gardé en mémoire JS ;
 *   il n'est pas stocké dans localStorage (lisible par tout script injecté).
 * - Toute requête modifiante porte l'en-tête X-CSRF-Token.
 */

let csrfToken = null;

export class ApiError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

async function request(method, path, { json, formData } = {}) {
  const headers = { Accept: "application/json" };
  let body;
  if (json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(json);
  } else if (formData) {
    body = formData; // le navigateur pose lui-même le boundary multipart
  }
  if (method !== "GET" && csrfToken) {
    headers["X-CSRF-Token"] = csrfToken;
  }

  const response = await fetch(`/api${path}`, {
    method,
    headers,
    body,
    credentials: "same-origin",
    cache: "no-store",
    redirect: "error",
  });

  if (response.status === 204) return null;
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    const err = data?.error ?? {};
    if (response.status === 401) csrfToken = null;
    throw new ApiError(response.status, err.code ?? "error", err.message ?? "Erreur réseau.", err.details);
  }
  if (data && typeof data.csrf_token === "string") csrfToken = data.csrf_token;
  return data;
}

export const api = {
  me: () => request("GET", "/auth/me"),
  login: (username, password) => request("POST", "/auth/login", { json: { username, password } }),
  register: (username, password) => request("POST", "/auth/register", { json: { username, password } }),
  logout: async () => {
    await request("POST", "/auth/logout");
    csrfToken = null;
  },
  changePassword: (current_password, new_password) =>
    request("POST", "/auth/change-password", { json: { current_password, new_password } }),

  listNotes: () => request("GET", "/notes"),
  getNote: (id) => request("GET", `/notes/${encodeURIComponent(id)}`),
  createNote: (title, content) => request("POST", "/notes", { json: { title, content } }),
  updateNote: (id, title, content) => request("PUT", `/notes/${encodeURIComponent(id)}`, { json: { title, content } }),
  deleteNote: (id) => request("DELETE", `/notes/${encodeURIComponent(id)}`),

  listFiles: () => request("GET", "/files"),
  uploadFile: (file) => {
    const fd = new FormData();
    fd.append("file", file);
    return request("POST", "/files", { formData: fd });
  },
  replaceFile: (id, file) => {
    const fd = new FormData();
    fd.append("file", file);
    return request("PUT", `/files/${encodeURIComponent(id)}`, { formData: fd });
  },
  deleteFile: (id) => request("DELETE", `/files/${encodeURIComponent(id)}`),
  downloadUrl: (id) => `/api/files/${encodeURIComponent(id)}/download`,

  listShares: (kind, id) => request("GET", `/${kind}/${encodeURIComponent(id)}/shares`),
  share: (kind, id, username, permission) =>
    request("POST", `/${kind}/${encodeURIComponent(id)}/shares`, { json: { username, permission } }),
  revokeShare: (shareId) => request("DELETE", `/shares/${encodeURIComponent(shareId)}`),
};

/** Message lisible pour l'utilisateur, détails de validation compris. */
export function errorMessage(err) {
  if (!(err instanceof ApiError)) return "Erreur inattendue.";
  if (err.details?.length) {
    return `${err.message} ${err.details.map((d) => d.message).join(" ; ")}`;
  }
  return err.message;
}
// GROGNON
