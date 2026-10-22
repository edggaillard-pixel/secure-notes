"""A03 — Injection SQL et XSS ; A05 — en-têtes et fuites d'erreurs."""
import pytest

from app.extensions import db
from app.models import User

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "admin'--",
    "' UNION SELECT password_hash FROM users--",
    "'; DROP TABLE users;--",
]
XSS_PAYLOAD = '<img src=x onerror="alert(document.cookie)"><script>alert(1)</script>'


@pytest.mark.parametrize("payload", SQLI_PAYLOADS)
def test_sqli_in_login_does_not_bypass_auth(alice, make_client, payload):
    resp = make_client().login(payload, payload)
    assert resp.status_code in (400, 401)          # jamais 200 ni 500
    assert db.session.execute(db.select(User)).scalars().first() is not None  # table intacte


@pytest.mark.parametrize("payload", SQLI_PAYLOADS)
def test_sqli_payload_is_stored_as_plain_data(alice, payload):
    created = alice.post("/api/notes", json={"title": payload, "content": payload})
    assert created.status_code == 201
    note = alice.get(f"/api/notes/{created.get_json()['id']}").get_json()
    # La donnée ressort strictement identique : elle n'a jamais été interprétée comme du SQL.
    assert note["title"] == payload and note["content"] == payload


def test_sqli_in_share_username_is_rejected_by_validation(alice):
    note_id = alice.post("/api/notes", json={"title": "t"}).get_json()["id"]
    resp = alice.post(f"/api/notes/{note_id}/shares",
                      json={"username": "bob' OR '1'='1", "permission": "read"})
    assert resp.status_code == 400


def test_xss_payload_is_returned_as_json_data_not_html(alice):
    created = alice.post("/api/notes", json={"title": XSS_PAYLOAD, "content": XSS_PAYLOAD})
    resp = alice.get(f"/api/notes/{created.get_json()['id']}")
    assert resp.mimetype == "application/json"
    assert resp.get_json()["content"] == XSS_PAYLOAD  # donnée intacte, échappée au rendu par React
    # Même ouverte directement, la réponse ne peut exécuter aucun script :
    assert "default-src 'none'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["X-Content-Type-Options"] == "nosniff"


def test_security_headers_on_api(alice):
    resp = alice.get("/api/notes")
    h = resp.headers
    assert h["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"]
    assert h["Referrer-Policy"] == "no-referrer"
    assert h["Cache-Control"] == "no-store"
    assert h["Cross-Origin-Opener-Policy"] == "same-origin"
    assert "Server" not in h


def test_errors_do_not_leak_internals(alice, app, monkeypatch):
    from app.api import notes

    def boom(*a, **k):
        raise RuntimeError("SELECT secret FROM internals /srv/app/secret.py")

    monkeypatch.setattr(notes, "_summary", boom)
    alice.post("/api/notes", json={"title": "t"})
    resp = alice.get("/api/notes")
    assert resp.status_code == 500
    body = resp.get_data(as_text=True)
    assert "SELECT" not in body and "Traceback" not in body and ".py" not in body
    assert resp.get_json()["error"]["code"] == "internal_error"


def test_unknown_route_returns_json_404(client):
    resp = client.get("/api/does-not-exist")
    assert resp.status_code == 404 and resp.is_json
# GROGNON
