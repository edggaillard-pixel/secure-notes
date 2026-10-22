"""A01 — Contrôle d'accès : IDOR, droits read/write/owner, gestion des partages."""
import uuid

import pytest

from .conftest import PNG_BYTES


@pytest.fixture
def alice_note(alice):
    return alice.post("/api/notes", json={"title": "secret", "content": "plans"}).get_json()["id"]


def test_unauthenticated_access_is_denied(client, alice_note):
    assert client.get("/api/notes").status_code == 401
    assert client.get(f"/api/notes/{alice_note}").status_code == 401


def test_idor_other_user_note_is_invisible(alice_note, bob):
    # Bob connaît l'UUID (fuite, devinette...) mais n'a aucun droit.
    assert bob.get(f"/api/notes/{alice_note}").status_code == 404
    assert bob.put(f"/api/notes/{alice_note}", json={"title": "pwned"}).status_code == 404
    assert bob.delete(f"/api/notes/{alice_note}").status_code == 404
    assert bob.get("/api/notes").get_json() == {"owned": [], "shared": []}


def test_inaccessible_and_nonexistent_look_identical(alice_note, bob):
    a = bob.get(f"/api/notes/{alice_note}")
    b = bob.get(f"/api/notes/{uuid.uuid4()}")
    assert a.status_code == b.status_code == 404 and a.get_json() == b.get_json()


def test_read_share(alice, alice_note, bob):
    assert alice.post(f"/api/notes/{alice_note}/shares",
                      json={"username": "bob", "permission": "read"}).status_code == 201
    assert bob.get(f"/api/notes/{alice_note}").get_json()["content"] == "plans"
    assert bob.put(f"/api/notes/{alice_note}", json={"title": "x"}).status_code == 404
    assert bob.delete(f"/api/notes/{alice_note}").status_code == 404


def test_write_share_cannot_delete_or_reshare(alice, alice_note, bob, make_client):
    alice.post(f"/api/notes/{alice_note}/shares", json={"username": "bob", "permission": "write"})
    assert bob.put(f"/api/notes/{alice_note}", json={"title": "edited", "content": "v2"}).status_code == 200
    assert bob.delete(f"/api/notes/{alice_note}").status_code == 404
    eve = make_client()
    eve.register("eve")
    # Bob ne peut pas étendre les droits à un tiers ni lister les partages.
    assert bob.post(f"/api/notes/{alice_note}/shares",
                    json={"username": "eve", "permission": "write"}).status_code == 404
    assert bob.get(f"/api/notes/{alice_note}/shares").status_code == 404


def test_revoked_share_removes_access(alice, alice_note, bob):
    share_id = alice.post(f"/api/notes/{alice_note}/shares",
                          json={"username": "bob", "permission": "read"}).get_json()["id"]
    assert alice.delete(f"/api/shares/{share_id}").status_code == 204
    assert bob.get(f"/api/notes/{alice_note}").status_code == 404


def test_third_party_cannot_delete_a_share(alice, alice_note, bob, make_client):
    share_id = alice.post(f"/api/notes/{alice_note}/shares",
                          json={"username": "bob", "permission": "read"}).get_json()["id"]
    eve = make_client()
    eve.register("eve")
    assert eve.delete(f"/api/shares/{share_id}").status_code == 404
    assert bob.get(f"/api/notes/{alice_note}").status_code == 200


def test_cannot_share_with_self_or_unknown(alice, alice_note):
    assert alice.post(f"/api/notes/{alice_note}/shares",
                      json={"username": "alice", "permission": "read"}).status_code == 400
    assert alice.post(f"/api/notes/{alice_note}/shares",
                      json={"username": "ghost", "permission": "read"}).status_code == 404


def test_privilege_escalation_via_permission_value(alice, alice_note):
    resp = alice.post(f"/api/notes/{alice_note}/shares",
                      json={"username": "bob", "permission": "owner"})
    assert resp.status_code == 400


def test_idor_on_files(alice, bob):
    file_id = alice.upload(PNG_BYTES, "pic.png").get_json()["id"]
    assert bob.get(f"/api/files/{file_id}/download").status_code == 404
    assert bob.delete(f"/api/files/{file_id}").status_code == 404
    assert bob.upload(PNG_BYTES, "evil.png", path=f"/api/files/{file_id}", method="PUT").status_code == 404
    alice.post(f"/api/files/{file_id}/shares", json={"username": "bob", "permission": "read"})
    assert bob.get(f"/api/files/{file_id}/download").status_code == 200
    assert bob.upload(PNG_BYTES, "evil.png", path=f"/api/files/{file_id}", method="PUT").status_code == 404
# GROGNON
