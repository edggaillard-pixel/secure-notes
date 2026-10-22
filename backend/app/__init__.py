"""
Fabrique de l'application Flask (application factory).

Ordre des protections pour chaque requête :
  ProxyFix (IP réelle) -> rate limiting -> vérification Origin
  -> chargement de la session -> route (login_required + CSRF + contrôle d'accès)
  -> en-têtes de sécurité sur la réponse.
"""
from __future__ import annotations

import logging

import click
from flask import Flask, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix

from .audit import setup_logging
from .config import Config
from .errors import register_error_handlers
from .extensions import db, limiter
from .security.crypto import KeyRing
from .security.headers import register_security_headers
from .security.request_guard import register_request_guard
from .security.sessions import load_current_session


def create_app(config: Config | None = None) -> Flask:
    app = Flask(__name__)
    cfg = config or Config.from_env()
    app.config.from_object(cfg)

    # Le mode debug de Werkzeug expose une console Python : interdit hors dev.
    app.debug = False

    setup_logging(logging.INFO)

    # Nginx est l'unique proxy de confiance : on ne lit QUE ses en-têtes
    # X-Forwarded-*. Sans cela, request.remote_addr serait l'IP de Nginx et
    # le rate limiting s'appliquerait à tout le monde en même temps ; avec
    # un nombre trop grand, un client pourrait usurper son IP.
    n = app.config["TRUSTED_PROXY_COUNT"]
    if n > 0:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=n, x_proto=n)

    app.extensions["keyring"] = KeyRing(app.config["DATA_ENCRYPTION_KEYS"])

    db.init_app(app)
    limiter.init_app(app)

    register_error_handlers(app)
    register_request_guard(app)
    app.before_request(load_current_session)
    register_security_headers(app)

    from .api import auth, files, notes, shares

    for module in (auth, notes, files, shares):
        app.register_blueprint(module.bp)

    @app.get("/api/health")
    @limiter.exempt
    def health():
        return jsonify({"status": "ok"})

    _register_cli(app)
    return app


def _register_cli(app: Flask) -> None:
    @app.cli.command("init-db")
    def init_db():
        """Crée les tables (idempotent)."""
        db.create_all()
        click.echo("Base initialisée.")

    @app.cli.command("purge-sessions")
    def purge_sessions():
        """Supprime les sessions expirées (à planifier via cron)."""
        from .models import Session, utcnow

        n = db.session.query(Session).filter(Session.expires_at <= utcnow()).delete()
        db.session.commit()
        click.echo(f"{n} session(s) expirée(s) supprimée(s).")
# GROGNON
