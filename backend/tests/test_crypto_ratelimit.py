"""A02 — Chiffrement au repos ; A07 — limitation de débit."""
import base64
import os

import pytest

from app import create_app
from app.extensions import db, limiter
from app.models import Note
from app.security.crypto import DecryptionError, KeyRing

from .conftest import ApiClient, make_config


def _key(kid):
    return f"{kid}:{base64.b64encode(os.urandom(32)).decode()}"


# --- Chiffrement -------------------------------------------------------------

def test_roundtrip_and_random_nonce():
    kr = KeyRing(_key(1))
    a, b = kr.encrypt(b"secret", "ctx"), kr.encrypt(b"secret", "ctx")
    assert a != b  # nonce aléatoire : même clair -> chiffrés différents
    assert kr.decrypt(a, "ctx") == b"secret"


def test_tampering_is_detected():
    kr = KeyRing(_key(1))
    blob = bytearray(kr.encrypt(b"secret", "ctx"))
    blob[-1] ^= 0x01
    with pytest.raises(DecryptionError):
        kr.decrypt(bytes(blob), "ctx")


def test_ciphertext_cannot_be_moved_to_another_record():
    kr = KeyRing(_key(1))
    blob = kr.encrypt(b"note de alice", "note:A:content")
    with pytest.raises(DecryptionError):
        kr.decrypt(blob, "note:B:content")  # AAD différente -> rejet


def test_key_rotation():
    old = _key(1)
    kr_old = KeyRing(old)
    blob = kr_old.encrypt(b"data", "ctx")
    kr_new = KeyRing(_key(2) + "," + old)  # nouvelle clé active, ancienne conservée
    assert kr_new.decrypt(blob, "ctx") == b"data"
    assert kr_new.needs_reencrypt(blob)
    assert not kr_new.needs_reencrypt(kr_new.encrypt(b"data", "ctx"))


def test_weak_or_malformed_keys_refused():
    with pytest.raises(ValueError):
        KeyRing("1:" + base64.b64encode(b"short").decode())
    with pytest.raises(ValueError):
        KeyRing("")


def test_notes_are_encrypted_in_database(alice):
    alice.post("/api/notes", json={"title": "Codes du coffre", "content": "1234-5678"})
    row = db.session.execute(db.select(Note)).scalar_one()
    assert b"Codes du coffre" not in row.title_enc
    assert b"1234-5678" not in row.content_enc


# --- Rate limiting -----------------------------------------------------------

def test_login_bruteforce_is_throttled_per_ip(client, alice):
    statuses = [client.login("alice", f"wrong-password-{i}").status_code for i in range(6)]
    assert statuses[:5] == [401] * 5
    assert statuses[5] == 429


def test_rate_limited_response_has_retry_after(client):
    for i in range(5):
        client.login("alice", f"wrong-{i}")
    resp = client.login("alice", "wrong")
    assert resp.status_code == 429 and "Retry-After" in resp.headers


def test_distributed_credential_stuffing_is_throttled_per_account(tmp_path):
    # Ici on simule Nginx devant l'appli : l'IP vient de X-Forwarded-For.
    app = create_app(make_config(tmp_path, TRUSTED_PROXY_COUNT=1))
    with app.app_context():
        db.create_all()
        limiter.reset()
        c = ApiClient(app.test_client())
        statuses = [
            c.login("victim", "guess", headers={"X-Forwarded-For": f"203.0.113.{i}"}).status_code
            for i in range(11)
        ]
        # Une IP différente à chaque essai : la limite par IP ne voit rien,
        # mais la limite par compte (10/h) bloque le 11e essai.
        assert statuses[:10] == [401] * 10
        assert statuses[10] == 429
        db.drop_all()
# GROGNON
