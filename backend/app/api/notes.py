"""
CRUD des notes.

- Contenus chiffrés au repos ; contexte AAD = "note:<id>:<champ>".
- Chaque accès passe par resolve_access (anti-IDOR).
- Aucune construction de SQL à la main : uniquement l'ORM (requêtes paramétrées).
- Le contenu est renvoyé tel quel en JSON ; c'est au rendu (React) de
  l'échapper. On n'« assainit » pas en entrée pour ne pas corrompre les
  données : l'échappement se fait au moment de l'affichage, selon le contexte.
"""
from __future__ import annotations

import uuid

from flask import Blueprint, g, jsonify

from . import iso
from ..audit import security_event
from ..extensions import db
from ..models import Note, Share, User, utcnow
from ..schemas import NoteIn, parse
from ..security.access import resolve_access
from ..security.crypto import keyring
from ..security.request_guard import json_body
from ..security.sessions import login_required

bp = Blueprint("notes", __name__, url_prefix="/api/notes")


def _ctx(note_id: uuid.UUID, field: str) -> str:
    return f"note:{note_id}:{field}"


def _summary(note: Note, permission: str, owner_name: str) -> dict:
    return {
        "id": str(note.id),
        "title": keyring().decrypt_str(note.title_enc, _ctx(note.id, "title")),
        "permission": permission,
        "owner": owner_name,
        "updated_at": iso(note.updated_at),
    }


def _full(note: Note, permission: str) -> dict:
    data = _summary(note, permission, note.owner.username)
    data["content"] = keyring().decrypt_str(note.content_enc, _ctx(note.id, "content"))
    data["created_at"] = iso(note.created_at)
    return data


@bp.get("")
@login_required
def list_notes():
    user: User = g.user
    owned = db.session.execute(
        db.select(Note).where(Note.owner_id == user.id).order_by(Note.updated_at.desc())
    ).scalars()
    shared = db.session.execute(
        db.select(Note, Share.permission, User.username)
        .join(Share, (Share.resource_id == Note.id) & (Share.resource_type == "note"))
        .join(User, User.id == Note.owner_id)
        .where(Share.grantee_id == user.id)
        .order_by(Note.updated_at.desc())
    ).all()
    return jsonify({
        "owned": [_summary(n, "owner", user.username) for n in owned],
        "shared": [_summary(n, perm, owner) for n, perm, owner in shared],
    })


@bp.post("")
@login_required
def create_note():
    payload = parse(NoteIn, json_body())
    note_id = uuid.uuid4()
    kr = keyring()
    note = Note(
        id=note_id,
        owner_id=g.user.id,
        title_enc=kr.encrypt_str(payload.title, _ctx(note_id, "title")),
        content_enc=kr.encrypt_str(payload.content, _ctx(note_id, "content")),
    )
    db.session.add(note)
    db.session.commit()
    return jsonify(_full(note, "owner")), 201


@bp.get("/<uuid:note_id>")
@login_required
def get_note(note_id: uuid.UUID):
    note, perm = resolve_access(Note, note_id, g.user, "read")
    return jsonify(_full(note, perm))


@bp.put("/<uuid:note_id>")
@login_required
def update_note(note_id: uuid.UUID):
    note, perm = resolve_access(Note, note_id, g.user, "write")
    payload = parse(NoteIn, json_body())
    kr = keyring()
    note.title_enc = kr.encrypt_str(payload.title, _ctx(note.id, "title"))
    note.content_enc = kr.encrypt_str(payload.content, _ctx(note.id, "content"))
    note.updated_at = utcnow()
    db.session.commit()
    return jsonify(_full(note, perm))


@bp.delete("/<uuid:note_id>")
@login_required
def delete_note(note_id: uuid.UUID):
    note, _ = resolve_access(Note, note_id, g.user, "owner")
    db.session.execute(
        db.delete(Share).where(Share.resource_type == "note", Share.resource_id == note.id)
    )
    db.session.delete(note)
    db.session.commit()
    security_event("note_delete", note_id=note_id)
    return "", 204
# GROGNON
