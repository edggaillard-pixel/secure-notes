"""A01 (CSRF) — Jeton synchronisé, vérification d'Origin, Content-Type JSON imposé."""


def test_state_change_without_csrf_token_is_rejected(alice):
    resp = alice.post("/api/notes", json={"title": "t", "content": "c"}, csrf=False)
    assert resp.status_code == 403
    assert resp.get_json()["error"]["code"] == "csrf_failed"


def test_state_change_with_wrong_csrf_token_is_rejected(alice):
    resp = alice.post("/api/notes", json={"title": "t"}, csrf=False,
                      headers={"X-CSRF-Token": "forged-token"})
    assert resp.status_code == 403


def test_csrf_token_of_another_session_is_rejected(alice, bob):
    resp = alice.post("/api/notes", json={"title": "t"}, csrf=False,
                      headers={"X-CSRF-Token": bob.csrf})
    assert resp.status_code == 403


def test_state_change_with_valid_token_succeeds(alice):
    assert alice.post("/api/notes", json={"title": "t", "content": "c"}).status_code == 201


def test_logout_requires_csrf(alice):
    # Sinon un site tiers pourrait déconnecter la victime (« logout CSRF »).
    assert alice.post("/api/auth/logout", csrf=False).status_code == 403


def test_foreign_origin_rejected_even_before_login(client):
    resp = client.login("alice", headers={"Origin": "https://evil.example"})
    assert resp.status_code == 403
    assert resp.get_json()["error"]["code"] == "origin_rejected"


def test_html_form_post_is_rejected(client):
    # Ce qu'enverrait un <form method=post> piégé sur un site tiers.
    resp = client.post("/api/auth/login", data={"username": "alice", "password": "x"})
    assert resp.status_code == 415


def test_get_requests_do_not_change_state(alice):
    # Les routes de modification n'acceptent pas GET (pas de CSRF via <img src>).
    assert alice.get("/api/auth/logout").status_code == 405
# GROGNON
