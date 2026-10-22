"""
Upload / téléchargement de fichiers.

Upload : validation (cf. security/uploads.py) -> chiffrement AES-GCM avec
AAD "file:<id>:data" -> écriture atomique sous un nom aléatoire, hors webroot.

Téléchargement : le fichier n'est jamais servi « statiquement » par Nginx ;
il passe par cette route qui vérifie les droits, déchiffre, contrôle
l'empreinte SHA-256, puis force le téléchargement :
- Content-Disposition: attachment  -> jamais rendu dans l'onglet ;
- X-Content-Type-Options: nosniff  -> pas de réinterprétation du type ;
- CSP "sandbox"                    -> même ouvert, aucun script ne s'exécuterait.
"""
from __future__ import annotations

import hashlib
import hmac
import uuid
from urllib.parse import quote

from flask import Blueprint, Response, current_app, g, jsonify, request

from . import iso
from ..audit import security_event
from ..errors import ApiError
from ..extensions import db, limiter
from ..models import Share, StoredFile, User, utcnow
from ..security.access import resolve_access
from ..security.crypto import keyring
from ..security.sessions import login_required
from ..security.uploads import (
    delete_blob,
    new_storage_name,
    read_blob,
    validate_upload,
    write_blob,
)

bp = Blueprint("files", __name__, url_prefix="/api/files")


def _ctx(file_id: uuid.UUID, field: str) -> str:
    return f"file:{file_id}:{field}"


def _meta(f: StoredFile, permission: str, owner_name: str) -> dict:
    return {
        "id": str(f.id),
        "name": keyring().decrypt_str(f.original_name_enc, _ctx(f.id, "name")),
        "mime_type": f.mime_type,
        "size": f.size_bytes,
        "permission": permission,
        "owner": owner_name,
        "updated_at": iso(f.updated_at),
    }


def content_disposition(name: str) -> str:
    """En-tête de téléchargement forcé (RFC 6266 / RFC 5987).

    Nom ASCII de repli + nom UTF-8 encodé. quote() encode guillemets, CR/LF,
    point-virgule... : impossible de fermer le paramètre ou d'injecter un
    en-tête (« HTTP response splitting »).
    """
    ascii_fallback = quote(name.encode("ascii", "ignore").decode() or "download", safe="._-")
    return f"attachment; filename=\"{ascii_fallback}\"; filename*=UTF-8''{quote(name, safe='')}"


def _store(file_id: uuid.UUID):
    """Valide l'upload courant, le chiffre et l'écrit. Renvoie (upload, storage_name)."""
    cfg = current_app.config
    upload = validate_upload(request.files.get("file"), cfg["MAX_UPLOAD_BYTES"])
    storage_name = new_storage_name()
    blob = keyring().encrypt(upload.data, _ctx(file_id, "data"))
    write_blob(cfg["UPLOAD_DIR"], storage_name, blob)
    return upload, storage_name


@bp.get("")
@login_required
def list_files():
    user: User = g.user
    owned = db.session.execute(
        db.select(StoredFile).where(StoredFile.owner_id == user.id).order_by(StoredFile.updated_at.desc())
    ).scalars()
    shared = db.session.execute(
        db.select(StoredFile, Share.permission, User.username)
        .join(Share, (Share.resource_id == StoredFile.id) & (Share.resource_type == "file"))
        .join(User, User.id == StoredFile.owner_id)
        .where(Share.grantee_id == user.id)
        .order_by(StoredFile.updated_at.desc())
    ).all()
    return jsonify({
        "owned": [_meta(f, "owner", user.username) for f in owned],
        "shared": [_meta(f, perm, owner) for f, perm, owner in shared],
    })


@bp.post("")
@login_required
@limiter.limit("30 per hour")
def upload_file():
    file_id = uuid.uuid4()
    try:
        upload, storage_name = _store(file_id)
    except ApiError as err:
        security_event("upload", "rejected", reason=err.code)
        raise
    kr = keyring()
    record = StoredFile(
        id=file_id,
        owner_id=g.user.id,
        storage_name=storage_name,
        original_name_enc=kr.encrypt_str(upload.display_name, _ctx(file_id, "name")),
        mime_type=upload.mime_type,
        size_bytes=len(upload.data),
        sha256=upload.sha256,
    )
    db.session.add(record)
    try:
        db.session.commit()
    except Exception:
        delete_blob(current_app.config["UPLOAD_DIR"], storage_name)  # pas de fichier orphelin
        raise
    security_event("upload", file_id=file_id, mime=upload.mime_type, size=len(upload.data))
    return jsonify(_meta(record, "owner", g.user.username)), 201


@bp.get("/<uuid:file_id>")
@login_required
def file_metadata(file_id: uuid.UUID):
    f, perm = resolve_access(StoredFile, file_id, g.user, "read")
    return jsonify(_meta(f, perm, f.owner.username))


@bp.get("/<uuid:file_id>/download")
@login_required
def download_file(file_id: uuid.UUID):
    f, _ = resolve_access(StoredFile, file_id, g.user, "read")
    blob = read_blob(current_app.config["UPLOAD_DIR"], f.storage_name)
    data = keyring().decrypt(blob, _ctx(f.id, "data"))
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), f.sha256):
        raise ApiError(500, "integrity_error", "Fichier corrompu.")
    name = keyring().decrypt_str(f.original_name_enc, _ctx(f.id, "name"))

    security_event("download", file_id=f.id)
    return Response(
        data,
        mimetype=f.mime_type,
        headers={
            "Content-Disposition": content_disposition(name),
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "X-Content-Type-Options": "nosniff",
        },
    )


@bp.put("/<uuid:file_id>")
@login_required
@limiter.limit("30 per hour")
def replace_file(file_id: uuid.UUID):
    """Droit « write » : remplacer le contenu du fichier par une nouvelle version."""
    f, perm = resolve_access(StoredFile, file_id, g.user, "write")
    upload, new_name = _store(f.id)
    old_name = f.storage_name
    f.storage_name = new_name
    f.original_name_enc = keyring().encrypt_str(upload.display_name, _ctx(f.id, "name"))
    f.mime_type = upload.mime_type
    f.size_bytes = len(upload.data)
    f.sha256 = upload.sha256
    f.updated_at = utcnow()
    try:
        db.session.commit()
    except Exception:
        delete_blob(current_app.config["UPLOAD_DIR"], new_name)
        raise
    delete_blob(current_app.config["UPLOAD_DIR"], old_name)
    security_event("file_replace", file_id=f.id)
    return jsonify(_meta(f, perm, f.owner.username))


@bp.delete("/<uuid:file_id>")
@login_required
def delete_file(file_id: uuid.UUID):
    f, _ = resolve_access(StoredFile, file_id, g.user, "owner")
    storage_name = f.storage_name
    db.session.execute(
        db.delete(Share).where(Share.resource_type == "file", Share.resource_id == f.id)
    )
    db.session.delete(f)
    db.session.commit()
    delete_blob(current_app.config["UPLOAD_DIR"], storage_name)
    security_event("file_delete", file_id=file_id)
    return "", 204
# GROGNON
