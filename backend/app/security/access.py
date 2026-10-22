"""
Contrôle d'accès aux ressources (A01 - Broken Access Control).

C'est le point le plus critique de l'application : la faille n°1 du
Top 10 OWASP. Règles appliquées :

1. Chaque accès à une note ou un fichier passe par `resolve_access`. Aucune
   route ne fait de `Note.query.get(id)` brut : c'est ce qui crée les IDOR
   (Insecure Direct Object Reference : changer l'id dans l'URL pour lire la
   ressource d'un autre).
2. Le niveau de droit est calculé côté serveur à partir de la base, jamais
   à partir de ce qu'envoie le client.
3. Une ressource inaccessible renvoie 404 et non 403 : on ne confirme pas
   à un attaquant qu'un identifiant existe.
4. Hiérarchie : owner > write > read. Seul le propriétaire peut supprimer
   la ressource ou gérer ses partages.
"""
from __future__ import annotations

import uuid
from typing import Literal, TypeVar

from ..errors import ApiError
from ..extensions import db
from ..models import Note, Share, StoredFile, User

Permission = Literal["read", "write", "owner"]
_RANK = {"read": 1, "write": 2, "owner": 3}

R = TypeVar("R", Note, StoredFile)
_TYPE_NAME = {Note: "note", StoredFile: "file"}


def permission_for(user: User, resource: Note | StoredFile) -> Permission | None:
    if resource.owner_id == user.id:
        return "owner"
    share = db.session.execute(
        db.select(Share.permission).where(
            Share.resource_type == _TYPE_NAME[type(resource)],
            Share.resource_id == resource.id,
            Share.grantee_id == user.id,
        )
    ).scalar_one_or_none()
    return share  # "read", "write" ou None


def resolve_access(model: type[R], resource_id: uuid.UUID, user: User, need: Permission) -> tuple[R, Permission]:
    """Charge la ressource si et seulement si `user` a au moins le droit `need`."""
    resource = db.session.get(model, resource_id)
    perm = permission_for(user, resource) if resource is not None else None
    if perm is None or _RANK[perm] < _RANK[need]:
        # Même réponse que « n'existe pas » : pas de fuite d'information.
        raise ApiError(404, "not_found", "Ressource introuvable.")
    return resource, perm
# GROGNON
