"""
En-têtes HTTP de sécurité posés par l'API (défense en profondeur).

Nginx pose déjà les en-têtes pour la SPA (cf. frontend/nginx/security-headers.conf).
On les repose ici pour l'API : si un jour l'API est exposée sans ce proxy,
ou si une réponse JSON est ouverte directement dans un onglet, elle reste
protégée.
"""
from __future__ import annotations

from flask import Flask, Response, request

# Une API JSON n'a besoin de charger aucune ressource : on interdit tout.
API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

BASE_HEADERS = {
    "Content-Security-Policy": API_CSP,
    # Empêche le navigateur de « deviner » un type MIME (ex. traiter un .txt
    # uploadé comme du HTML exécutable).
    "X-Content-Type-Options": "nosniff",
    # Anti-clickjacking (doublon volontaire de frame-ancestors pour les vieux navigateurs).
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
}


def register_security_headers(app: Flask) -> None:
    @app.after_request
    def apply_headers(response: Response) -> Response:
        for name, value in BASE_HEADERS.items():
            response.headers.setdefault(name, value)
        if request.path.startswith("/api/"):
            # Données personnelles : aucun cache navigateur ni proxy intermédiaire.
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        # Ne pas annoncer la techno serveur (« Werkzeug/x.y Python/x.y »).
        response.headers.pop("Server", None)
        return response
# GROGNON
