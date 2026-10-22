"""
Configuration de l'application.

Principe : aucun secret dans le code (A02/A05). Tout vient de variables
d'environnement, et l'application refuse de démarrer si un secret obligatoire
manque ou est trop faible (« fail closed » plutôt que « fail open »).
"""
from __future__ import annotations

import os
from datetime import timedelta


class ConfigError(RuntimeError):
    """Levée quand la configuration est absente ou dangereuse."""


def _require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ConfigError(f"Variable d'environnement obligatoire manquante : {name}")
    return value


class Config:
    # --- Base de données ---------------------------------------------------
    # L'ORM SQLAlchemy génère des requêtes paramétrées (A03 - Injection).
    SQLALCHEMY_DATABASE_URI: str = ""
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

    # --- Sessions ----------------------------------------------------------
    # Préfixe __Host- : le navigateur impose Secure, Path=/ et l'absence de
    # Domain, ce qui empêche un sous-domaine compromis d'écraser le cookie.
    SESSION_COOKIE_NAME = "__Host-sid"
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = "Strict"
    SESSION_ABSOLUTE_LIFETIME = timedelta(hours=8)   # durée max, même si actif
    SESSION_IDLE_TIMEOUT = timedelta(minutes=30)     # expiration sur inactivité

    # --- Rate limiting -----------------------------------------------------
    RATELIMIT_STORAGE_URI = "memory://"
    RATELIMIT_DEFAULT = "300 per minute"
    RATELIMIT_LOGIN = "5 per minute;20 per hour"
    RATELIMIT_LOGIN_PER_ACCOUNT = "10 per hour"
    RATELIMIT_REGISTER = "5 per hour"
    RATELIMIT_HEADERS_ENABLED = True

    # --- Uploads -----------------------------------------------------------
    UPLOAD_DIR = "/data/uploads"                 # hors de la racine web
    MAX_UPLOAD_BYTES = 10 * 1024 * 1024          # 10 Mo
    # Marge pour l'enveloppe multipart ; au-delà, Werkzeug renvoie 413
    # avant même de lire le corps de la requête.
    MAX_CONTENT_LENGTH = MAX_UPLOAD_BYTES + 64 * 1024

    # --- Chiffrement au repos ----------------------------------------------
    # Format : "kid:clé_base64[,kid:clé_base64...]" ; la première est active.
    DATA_ENCRYPTION_KEYS = ""

    # --- CSRF / origine ----------------------------------------------------
    ALLOWED_ORIGINS: tuple[str, ...] = ()

    # --- Divers ------------------------------------------------------------
    TRUSTED_PROXY_COUNT = 1   # Nginx devant Flask (pour l'IP réelle du client)
    JSON_SORT_KEYS = False
    DEBUG = False
    TESTING = False

    @classmethod
    def from_env(cls) -> "Config":
        cfg = cls()
        cfg.SQLALCHEMY_DATABASE_URI = _require("DATABASE_URL")
        cfg.DATA_ENCRYPTION_KEYS = _require("DATA_ENCRYPTION_KEYS")
        cfg.RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
        cfg.UPLOAD_DIR = os.environ.get("UPLOAD_DIR", cls.UPLOAD_DIR)
        origins = os.environ.get("ALLOWED_ORIGINS", "")
        cfg.ALLOWED_ORIGINS = tuple(o.strip() for o in origins.split(",") if o.strip())
        if not cfg.ALLOWED_ORIGINS:
            raise ConfigError("ALLOWED_ORIGINS doit lister au moins une origine")
        cfg.TRUSTED_PROXY_COUNT = int(os.environ.get("TRUSTED_PROXY_COUNT", "1"))
        return cfg
# GROGNON
