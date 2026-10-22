"""
Gestion centralisée des erreurs (A05 - Security Misconfiguration).

Règle : le client ne reçoit jamais de trace d'exécution, de requête SQL ou
de chemin de fichier. Il reçoit un code d'erreur stable et un message
générique ; le détail technique part uniquement dans les logs serveur.
"""
from __future__ import annotations

import logging

from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException

log = logging.getLogger("app.errors")


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, details: list | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details


def _payload(code: str, message: str, details: list | None = None):
    body = {"error": {"code": code, "message": message}}
    if details:
        body["error"]["details"] = details
    return body


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(ApiError)
    def handle_api_error(err: ApiError):
        return jsonify(_payload(err.code, err.message, err.details)), err.status

    @app.errorhandler(HTTPException)
    def handle_http(err: HTTPException):
        # 404, 405, 413 (fichier trop gros), 429 (rate limit)...
        code = (err.name or "error").lower().replace(" ", "_")
        messages = {
            413: "Fichier trop volumineux.",
            429: "Trop de requêtes, réessayez plus tard.",
        }
        msg = messages.get(err.code or 500, err.name or "Erreur")
        response = jsonify(_payload(code, msg))
        response.status_code = err.code or 500
        # Conserve l'en-tête Retry-After posé par Flask-Limiter.
        if err.code == 429 and getattr(err, "response", None) is not None:
            for h in ("Retry-After",):
                if h in err.response.headers:
                    response.headers[h] = err.response.headers[h]
        return response

    @app.errorhandler(Exception)
    def handle_unexpected(err: Exception):
        log.exception("Erreur non gérée")  # détail uniquement côté serveur
        return jsonify(_payload("internal_error", "Erreur interne.")), 500
# GROGNON
