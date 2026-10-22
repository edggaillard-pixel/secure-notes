"""
Garde-fous appliqués à toutes les requêtes avant le routage.

1. Vérification de l'en-tête Origin (OWASP CSRF Cheat Sheet, « Verifying
   origin with standard headers ») : toute requête modifiante venant d'une
   origine non autorisée est rejetée, y compris sur /login et /register qui
   n'ont pas encore de session (protection contre le « login CSRF »).
2. Les corps JSON doivent être envoyés avec Content-Type: application/json.
   Un formulaire HTML cross-site ne peut envoyer que
   application/x-www-form-urlencoded, multipart/form-data ou text/plain :
   exiger du JSON ferme donc la porte aux CSRF « classiques ».
"""
from __future__ import annotations

from typing import Any

from flask import Flask, current_app, request

from ..errors import ApiError
from .sessions import SAFE_METHODS


def register_request_guard(app: Flask) -> None:
    @app.before_request
    def check_origin():
        if request.method in SAFE_METHODS:
            return None
        origin = request.headers.get("Origin")
        if origin is None:
            # Pas d'Origin : clients non-navigateurs (curl, tests). Ils n'ont
            # pas de cookies d'une victime, donc pas de risque CSRF ici ;
            # le jeton CSRF reste exigé sur les routes authentifiées.
            return None
        if origin not in current_app.config["ALLOWED_ORIGINS"]:
            raise ApiError(403, "origin_rejected", "Origine non autorisée.")
        return None


def json_body() -> dict[str, Any]:
    """Lit un corps JSON en imposant le Content-Type et un objet à la racine."""
    if not request.is_json:
        raise ApiError(415, "unsupported_media_type", "Content-Type application/json requis.")
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError(400, "invalid_json", "Corps JSON invalide.")
    return data
# GROGNON
