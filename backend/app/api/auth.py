"""
Authentification : inscription, connexion, déconnexion, changement de mot de passe.

Protections notables :
- Rate limiting à deux niveaux sur /login : par IP (force brute classique)
  et par compte visé (credential stuffing distribué sur beaucoup d'IP).
- Message d'erreur unique « identifiants invalides » + hash factice pour
  les comptes inexistants : pas d'énumération par message ni par timing.
- Nouvelle session à chaque connexion (anti « session fixation »).
- Changement de mot de passe -> révocation de toutes les autres sessions.
"""
from __future__ import annotations

from flask import Blueprint, current_app, g, jsonify, make_response, request

from ..audit import security_event
from ..errors import ApiError
from ..extensions import db, limiter
from ..models import User
from ..schemas import ChangePasswordIn, LoginIn, RegisterIn, parse
from ..security.passwords import hash_password, needs_rehash, verify_password
from ..security.request_guard import json_body
from ..security.sessions import (
    clear_session_cookie,
    create_session,
    login_required,
    revoke_all_sessions,
    revoke_session,
    set_session_cookie,
)

bp = Blueprint("auth", __name__, url_prefix="/api/auth")


def _account_key() -> str:
    """Clé de rate limiting = compte visé (normalisé), indépendamment de l'IP."""
    data = request.get_json(silent=True)
    username = data.get("username") if isinstance(data, dict) else None
    if not isinstance(username, str):
        username = ""
    return "login-account:" + username.strip().lower()[:32]


def _user_payload(user: User, csrf_token: str) -> dict:
    return {"user": {"id": str(user.id), "username": user.username}, "csrf_token": csrf_token}


def _start_session(user: User, status: int = 200):
    # Si un cookie de session existait déjà, on le révoque : la session
    # authentifiée a TOUJOURS un nouveau jeton (anti session fixation).
    if g.get("session") is not None:
        revoke_session(g.session)
    sess, token = create_session(user)
    db.session.commit()
    response = make_response(jsonify(_user_payload(user, sess.csrf_token)), status)
    set_session_cookie(response, token)
    return response


@bp.post("/register")
@limiter.limit(lambda: current_app.config["RATELIMIT_REGISTER"])
def register():
    payload = parse(RegisterIn, json_body())
    username = payload.username.lower()
    exists = db.session.execute(db.select(User.id).where(User.username == username)).first()
    if exists:
        # Énumération possible par l'inscription : risque accepté et documenté
        # (inhérent à tout identifiant unique), atténué par le rate limit.
        raise ApiError(409, "username_taken", "Cet identifiant n'est pas disponible.")
    user = User(username=username, password_hash=hash_password(payload.password))
    db.session.add(user)
    db.session.flush()
    security_event("register", user_id=user.id)
    return _start_session(user, status=201)


@bp.post("/login")
@limiter.limit(lambda: current_app.config["RATELIMIT_LOGIN"])
@limiter.limit(
    lambda: current_app.config["RATELIMIT_LOGIN_PER_ACCOUNT"],
    key_func=_account_key,
    # Seuls les échecs consomment le quota par compte : un utilisateur
    # légitime qui se connecte souvent n'est pas bloqué.
    deduct_when=lambda response: response.status_code == 401,
)
def login():
    payload = parse(LoginIn, json_body())
    username = payload.username.strip().lower()
    user = db.session.execute(db.select(User).where(User.username == username)).scalar_one_or_none()

    # verify_password fait un vrai calcul Argon2 même si user est None.
    if not verify_password(user.password_hash if user else None, payload.password):
        security_event("login", "failure", username=username)
        raise ApiError(401, "invalid_credentials", "Identifiant ou mot de passe incorrect.")

    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(payload.password)
    security_event("login", user_id=user.id)
    return _start_session(user)


@bp.post("/logout")
@login_required
def logout():
    security_event("logout")
    revoke_session(g.session)
    db.session.commit()
    response = make_response("", 204)
    clear_session_cookie(response)
    return response


@bp.get("/me")
def me():
    """Renvoie l'utilisateur courant et le jeton CSRF à utiliser par le front."""
    if g.get("user") is None:
        raise ApiError(401, "unauthenticated", "Authentification requise.")
    return jsonify(_user_payload(g.user, g.session.csrf_token))


@bp.post("/change-password")
@login_required
@limiter.limit("5 per hour")
def change_password():
    payload = parse(ChangePasswordIn, json_body())
    user: User = g.user
    if not verify_password(user.password_hash, payload.current_password):
        security_event("password_change", "failure")
        raise ApiError(403, "invalid_credentials", "Mot de passe actuel incorrect.")
    if user.username in payload.new_password.lower():
        raise ApiError(400, "validation_error", "Le mot de passe ne doit pas contenir l'identifiant.")
    user.password_hash = hash_password(payload.new_password)
    # Toutes les sessions (y compris celle-ci) sont révoquées, puis une
    # nouvelle est émise : un éventuel voleur de cookie est déconnecté.
    revoke_all_sessions(user)
    g.session = None
    security_event("password_change")
    return _start_session(user)
# GROGNON
