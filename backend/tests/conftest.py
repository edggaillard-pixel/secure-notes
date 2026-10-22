"""
Fixtures pytest.

Les tests tournent sur SQLite (rapide, sans Docker) : l'application n'utilise
que l'ORM, donc le comportement de sécurité testé est identique sur PostgreSQL.
Toutes les requêtes passent en HTTPS simulé pour que les cookies Secure circulent.
"""
from __future__ import annotations

import base64
import io
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app  # noqa: E402
from app.config import Config  # noqa: E402
from app.extensions import db, limiter  # noqa: E402

ORIGIN = "https://localhost"
PASSWORD = "correct-horse-battery-staple"
TEST_KEY = "1:" + base64.b64encode(b"k" * 32).decode()


def make_config(tmp_path, **overrides) -> Config:
    cfg = Config()
    cfg.TESTING = True
    cfg.SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'test.db'}"
    cfg.DATA_ENCRYPTION_KEYS = TEST_KEY
    cfg.UPLOAD_DIR = str(tmp_path / "uploads")
    cfg.ALLOWED_ORIGINS = (ORIGIN,)
    cfg.TRUSTED_PROXY_COUNT = 0
    cfg.RATELIMIT_STORAGE_URI = "memory://"
    for key, value in overrides.items():
        setattr(cfg, key, value)
    return cfg


class ApiClient:
    """Petit wrapper : HTTPS, en-tête Origin et jeton CSRF automatiques."""

    def __init__(self, flask_client):
        self.c = flask_client
        self.csrf: str | None = None

    def _headers(self, extra=None, csrf=True):
        h = {"Origin": ORIGIN}
        if csrf and self.csrf:
            h["X-CSRF-Token"] = self.csrf
        h.update(extra or {})
        return h

    def request(self, method, path, json=None, data=None, headers=None, csrf=True, **kw):
        resp = self.c.open(
            path,
            method=method,
            json=json,
            data=data,
            headers=self._headers(headers, csrf),
            base_url="https://localhost",
            **kw,
        )
        if resp.is_json and isinstance(resp.get_json(), dict) and "csrf_token" in resp.get_json():
            self.csrf = resp.get_json()["csrf_token"]
        return resp

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, **kw):
        return self.request("POST", path, **kw)

    def put(self, path, **kw):
        return self.request("PUT", path, **kw)

    def delete(self, path, **kw):
        return self.request("DELETE", path, **kw)

    def register(self, username, password=PASSWORD):
        return self.post("/api/auth/register", json={"username": username, "password": password})

    def login(self, username, password=PASSWORD, **kw):
        return self.post("/api/auth/login", json={"username": username, "password": password}, **kw)

    def upload(self, content: bytes, filename: str, path="/api/files", method="POST"):
        return self.request(
            method, path, data={"file": (io.BytesIO(content), filename)},
            content_type="multipart/form-data",
        )


@pytest.fixture
def app(tmp_path):
    application = create_app(make_config(tmp_path))
    with application.app_context():
        db.create_all()
        limiter.reset()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return ApiClient(app.test_client())


@pytest.fixture
def make_client(app):
    return lambda: ApiClient(app.test_client())


@pytest.fixture
def alice(make_client):
    c = make_client()
    assert c.register("alice").status_code == 201
    return c


@pytest.fixture
def bob(make_client):
    c = make_client()
    assert c.register("bob").status_code == 201
    return c


# Échantillons de fichiers « réels » (en-têtes magiques corrects)
PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00"
    b"\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xf8\xff\xff?\x00\x05\xfe\x02\xfe\xa7\x35\x81\x84"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)
PDF_BYTES = (
    b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[]/Count 0>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n"
)
# GROGNON
