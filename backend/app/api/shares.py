"""
Partage nominatif de notes et de fichiers.

- Seul le propriétaire peut lister, créer ou modifier les partages.
- Un bénéficiaire peut retirer son propre accès (« quitter le partage »).
- Rate limit sur la création : chercher un identifiant inexistant renvoie
  404, ce qui permet de tester l'existence de comptes. Risque accepté
  (nécessaire à l'UX) mais freiné par la limitation de débit.
"""
from __future__ import annotations

import uuid

from flask import Blueprint, g, jsonify

from . import iso
from ..audit import security_event
from ..errors import ApiError
from ..extensions import db, limiter
from ..models import Note, Share, StoredFile, User
from ..schemas import ShareIn, parse
from ..security.access import resolve_access
from ..security.request_guard import json_body
from ..security.sessions import login_required

bp = Blueprint("shares", __name__, url_prefix="/api")

_RESOURCES = {"notes": (Note, "note"), "files": (StoredFile, "file")}


def _resource(kind: str, resource_id: uuid.UUID):
    if kind not in _RESOURCES:
        raise ApiError(404, "not_found", "Ressource introuvable.")
    model, type_name = _RESOURCES[kind]
    resource, _ = resolve_access(model, resource_id, g.user, "owner")
    return resource, type_name


def _share_json(share: Share, username: str) -> dict:
    return {
        "id": str(share.id),
        "username": username,
        "permission": share.permission,
        "created_at": iso(share.created_at),
    }


@bp.get("/<kind>/<uuid:resource_id>/shares")
@login_required
def list_shares(kind: str, resource_id: uuid.UUID):
    resource, type_name = _resource(kind, resource_id)
    rows = db.session.execute(
        db.select(Share, User.username)
        .join(User, User.id == Share.grantee_id)
        .where(Share.resource_type == type_name, Share.resource_id == resource.id)
        .order_by(User.username)
    ).all()
    return jsonify([_share_json(s, name) for s, name in rows])


@bp.post("/<kind>/<uuid:resource_id>/shares")
@login_required
@limiter.limit("60 per hour")
def create_share(kind: str, resource_id: uuid.UUID):
    resource, type_name = _resource(kind, resource_id)
    payload = parse(ShareIn, json_body())
    grantee = db.session.execute(
        db.select(User).where(User.username == payload.username.lower())
    ).scalar_one_or_none()
    if grantee is None:
        raise ApiError(404, "user_not_found", "Utilisateur introuvable.")
    if grantee.id == g.user.id:
        raise ApiError(400, "invalid_share", "Impossible de partager avec soi-même.")

    share = db.session.execute(
        db.select(Share).where(
            Share.resource_type == type_name,
            Share.resource_id == resource.id,
            Share.grantee_id == grantee.id,
        )
    ).scalar_one_or_none()
    status = 200
    if share is None:
        share = Share(
            resource_type=type_name,
            resource_id=resource.id,
            owner_id=g.user.id,
            grantee_id=grantee.id,
            permission=payload.permission,
        )
        db.session.add(share)
        status = 201
    else:
        share.permission = payload.permission  # mise à jour du niveau de droit
    db.session.commit()
    security_event("share_grant", resource=f"{type_name}:{resource.id}",
                   grantee_id=grantee.id, permission=payload.permission)
    return jsonify(_share_json(share, grantee.username)), status


@bp.delete("/shares/<uuid:share_id>")
@login_required
def delete_share(share_id: uuid.UUID):
    share = db.session.get(Share, share_id)
    # Le propriétaire peut révoquer, le bénéficiaire peut se retirer.
    # Pour toute autre personne : 404 (pas de fuite d'existence).
    if share is None or g.user.id not in (share.owner_id, share.grantee_id):
        raise ApiError(404, "not_found", "Ressource introuvable.")
    db.session.delete(share)
    db.session.commit()
    security_event("share_revoke", share_id=share_id)
    return "", 204
# GROGNON
