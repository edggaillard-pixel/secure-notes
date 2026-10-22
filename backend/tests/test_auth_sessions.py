"""A02 / A07 — Hachage, cookies de session, fixation, révocation, expiration."""
from datetime import timedelta

from app.extensions import db
from app.models import Session, User, utcnow

from .conftest import PASSWORD


def _set_cookie_header(resp):
    return [h for h in resp.headers.getlist("Set-Cookie") if h.startswith("__Host-sid=")][0]


def test_session_cookie_is_hardened(client):
    resp = client.register("alice")
    assert resp.status_code == 201
    cookie = _set_cookie_header(resp)
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite=Strict" in cookie
    assert "Path=/" in cookie
    assert "Domain" not in cookie  # exigé par le préfixe __Host-


def test_password_is_stored_with_argon2id(client, app):
    client.register("alice")
    user = db.session.execute(db.select(User).where(User.username == "alice")).scalar_one()
    assert user.password_hash.startswith("$argon2id$")
    assert PASSWORD not in user.password_hash


def test_session_token_is_stored_hashed(client, app):
    resp = client.register("alice")
    token = _set_cookie_header(resp).split(";")[0].split("=", 1)[1]
    stored = db.session.execute(db.select(Session.token_hash)).scalar_one()
    assert stored != token and len(stored) == 64


def test_weak_passwords_rejected(client):
    assert client.register("alice", "short").status_code == 400
    assert client.register("alice", "password1234").status_code == 400
    assert client.register("alice", "alice-is-my-password").status_code == 400


def test_mass_assignment_rejected(client):
    resp = client.post("/api/auth/register",
                       json={"username": "eve", "password": PASSWORD, "is_admin": True})
    assert resp.status_code == 400


def test_login_errors_do_not_reveal_account_existence(alice, make_client):
    c = make_client()
    wrong_pwd = c.login("alice", "not-the-right-password")
    unknown = c.login("nobody", "not-the-right-password")
    assert wrong_pwd.status_code == unknown.status_code == 401
    assert wrong_pwd.get_json() == unknown.get_json()


def test_new_session_on_login_prevents_fixation(alice):
    before = alice.c.get_cookie("__Host-sid").value
    resp = alice.login("alice")
    assert resp.status_code == 200
    after = alice.c.get_cookie("__Host-sid").value
    assert before != after
    # L'ancien jeton est révoqué côté serveur.
    assert db.session.get(Session, __import__("hashlib").sha256(before.encode()).hexdigest()) is None


def test_logout_revokes_session_server_side(alice):
    stolen = alice.c.get_cookie("__Host-sid").value
    assert alice.post("/api/auth/logout").status_code == 204
    # Un attaquant qui aurait copié le cookie ne peut plus l'utiliser.
    alice.c.set_cookie("__Host-sid", stolen, domain="localhost", secure=True)
    assert alice.get("/api/auth/me").status_code == 401


def test_change_password_revokes_other_sessions(alice, make_client):
    other_device = make_client()
    assert other_device.login("alice").status_code == 200
    resp = alice.post("/api/auth/change-password",
                      json={"current_password": PASSWORD, "new_password": "another-long-passphrase"})
    assert resp.status_code == 200
    assert other_device.get("/api/auth/me").status_code == 401
    assert alice.get("/api/auth/me").status_code == 200


def test_idle_session_expires(alice):
    sess = db.session.execute(db.select(Session)).scalar_one()
    sess.last_seen_at = utcnow() - timedelta(minutes=31)
    db.session.commit()
    assert alice.get("/api/auth/me").status_code == 401


def test_absolute_session_lifetime(alice):
    sess = db.session.execute(db.select(Session)).scalar_one()
    sess.expires_at = utcnow() - timedelta(seconds=1)
    db.session.commit()
    assert alice.get("/api/auth/me").status_code == 401
# GROGNON
