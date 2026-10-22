"""
Gestion des sessions côté serveur (A07 - Identification and Authentication Failures).

Pourquoi pas la session Flask par défaut ? Elle est stockée *dans* le cookie
(signée, non chiffrée) : impossible de la révoquer côté serveur avant son
expiration. Ici :
- le cookie ne contient qu'un jeton opaque de 256 bits (secrets.token_urlsafe) ;
- la base ne stocke que SHA-256(jeton) ;
- logout / changement de mot de passe = suppression des lignes -> révocation
  immédiate, même si le cookie a été volé.

Attributs du cookie :
- HttpOnly  : inaccessible à JavaScript -> un XSS ne peut pas voler la session.
- Secure    : jamais envoyé en HTTP clair.
- SameSite=Strict : jamais envoyé sur une requête initiée par un autre site
  -> première barrière contre le CSRF.
- Préfixe __Host- : force Secure + Path=/ + pas d'attribut Domain.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import timedelta
from functools import wraps
from typing import Callable

from flask import Response, current_app, g, request

from ..errors import ApiError
from ..extensions import db
from ..models import Session, User, utcnow

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
CSRF_HEADER = "X-CSRF-Token"
_TOUCH_INTERVAL = timedelta(minutes=1)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(user: User) -> tuple[Session, str]:
    """Crée une nouvelle session et renvoie (session, jeton en clair pour le cookie)."""
    token = secrets.token_urlsafe(32)  # 256 bits d'entropie
    now = utcnow()
    sess = Session(
        token_hash=_hash_token(token),
        user_id=user.id,
        csrf_token=secrets.token_urlsafe(32),
        created_at=now,
        last_seen_at=now,
        expires_at=now + current_app.config["SESSION_ABSOLUTE_LIFETIME"],
    )
    db.session.add(sess)
    return sess, token


def set_session_cookie(response: Response, token: str) -> None:
    cfg = current_app.config
    response.set_cookie(
        cfg["SESSION_COOKIE_NAME"],
        token,
        max_age=int(cfg["SESSION_ABSOLUTE_LIFETIME"].total_seconds()),
        path="/",
        secure=cfg["SESSION_COOKIE_SECURE"],
        httponly=True,
        samesite=cfg["SESSION_COOKIE_SAMESITE"],
    )


def clear_session_cookie(response: Response) -> None:
    cfg = current_app.config
    response.delete_cookie(
        cfg["SESSION_COOKIE_NAME"],
        path="/",
        secure=cfg["SESSION_COOKIE_SECURE"],
        httponly=True,
        samesite=cfg["SESSION_COOKIE_SAMESITE"],
    )


def load_current_session() -> None:
    """before_request : résout le cookie en (g.session, g.user) si valide."""
    g.session = None
    g.user = None
    token = request.cookies.get(current_app.config["SESSION_COOKIE_NAME"])
    if not token or len(token) > 128:
        return
    sess = db.session.get(Session, _hash_token(token))
    if sess is None:
        return
    now = utcnow()
    idle = current_app.config["SESSION_IDLE_TIMEOUT"]
    if sess.expires_at <= now or sess.last_seen_at + idle <= now:
        # Session expirée : on la supprime pour ne pas la laisser traîner.
        db.session.delete(sess)
        db.session.commit()
        return
    if now - sess.last_seen_at >= _TOUCH_INTERVAL:
        sess.last_seen_at = now  # expiration glissante, écriture limitée
        db.session.commit()
    g.session = sess
    g.user = sess.user


def revoke_session(sess: Session) -> None:
    db.session.delete(sess)


def revoke_all_sessions(user: User, except_hash: str | None = None) -> int:
    q = db.session.query(Session).filter(Session.user_id == user.id)
    if except_hash:
        q = q.filter(Session.token_hash != except_hash)
    return q.delete(synchronize_session=False)


def verify_csrf() -> None:
    """Pattern « synchronizer token » (OWASP CSRF Cheat Sheet).

    Le jeton CSRF est lié à la session côté serveur et transmis au front via
    GET /api/auth/me. Le front le renvoie dans l'en-tête X-CSRF-Token.
    Un site tiers ne peut ni lire ce jeton (Same-Origin Policy) ni poser
    un en-tête personnalisé sur une requête cross-site sans préflight CORS
    (et nous n'autorisons aucune origine CORS).
    """
    sent = request.headers.get(CSRF_HEADER, "")
    expected = g.session.csrf_token if g.session else ""
    # compare_digest : comparaison en temps constant (pas de fuite temporelle).
    if not sent or not expected or not hmac.compare_digest(sent, expected):
        raise ApiError(403, "csrf_failed", "Jeton CSRF manquant ou invalide.")


def login_required(view: Callable) -> Callable:
    """Exige une session valide et, pour les méthodes non sûres, un jeton CSRF valide."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.get("user") is None:
            raise ApiError(401, "unauthenticated", "Authentification requise.")
        if request.method not in SAFE_METHODS:
            verify_csrf()
        return view(*args, **kwargs)

    return wrapper
# GROGNON
