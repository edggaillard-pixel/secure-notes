"""
Module d'upload sécurisé (OWASP File Upload Cheat Sheet).

Menaces traitées :
- Exécution de code / XSS stocké via un fichier piégé (.php, .html, .svg) :
  -> type MIME RÉEL détecté par libmagic sur les octets (pas l'extension,
     pas le Content-Type envoyé par le client, tous deux falsifiables) ;
  -> liste blanche stricte ; SVG et HTML exclus car ils peuvent contenir du JS ;
  -> extension déclarée cohérente avec le type détecté (bloque « facture.pdf »
     qui serait en réalité un ZIP, et l'inverse).
- Path traversal (« ../../etc/passwd ») : le nom d'origine n'est JAMAIS
  utilisé dans un chemin ; le fichier est stocké sous 32 caractères hexa
  aléatoires, dans un répertoire hors de la racine web.
- Déni de service par fichier énorme : limite de taille côté Nginx
  (client_max_body_size), côté Flask (MAX_CONTENT_LENGTH) et ici.
- Lecture directe du disque : contenu chiffré en AES-256-GCM, fichiers en 0600.
"""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import tempfile
import unicodedata
from dataclasses import dataclass

import magic
from werkzeug.datastructures import FileStorage

from ..errors import ApiError

# Type MIME détecté -> extensions acceptées pour ce type.
ALLOWED_TYPES: dict[str, frozenset[str]] = {
    "application/pdf": frozenset({".pdf"}),
    "image/png": frozenset({".png"}),
    "image/jpeg": frozenset({".jpg", ".jpeg"}),
    "image/webp": frozenset({".webp"}),
    "image/gif": frozenset({".gif"}),
    "text/plain": frozenset({".txt", ".md", ".log", ".csv"}),
    "text/csv": frozenset({".csv"}),
}

_STORAGE_NAME_RE = re.compile(r"^[0-9a-f]{32}$")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_MAX_NAME_LEN = 200
_SNIFF_BYTES = 64 * 1024


@dataclass(frozen=True)
class ValidatedUpload:
    data: bytes
    display_name: str
    mime_type: str
    sha256: str


def sanitize_display_name(raw: str) -> str:
    """Nom affichable uniquement (jamais utilisé comme chemin).

    Retire les composants de chemin, les caractères de contrôle et les
    séparateurs, normalise l'Unicode (NFC) et tronque la longueur.
    """
    name = unicodedata.normalize("NFC", raw or "")
    name = name.replace("\\", "/").split("/")[-1]       # garde le dernier segment
    name = _CONTROL_CHARS_RE.sub("", name)
    name = name.strip().strip(".")                      # pas de « .. » ni de nom caché
    if len(name) > _MAX_NAME_LEN:
        stem, ext = os.path.splitext(name)
        name = stem[: _MAX_NAME_LEN - len(ext)] + ext
    return name


def detect_mime(data: bytes) -> str:
    return magic.from_buffer(data[:_SNIFF_BYTES], mime=True)


def validate_upload(file: FileStorage | None, max_bytes: int) -> ValidatedUpload:
    if file is None or not file.filename:
        raise ApiError(400, "no_file", "Aucun fichier fourni.")

    display_name = sanitize_display_name(file.filename)
    ext = os.path.splitext(display_name)[1].lower()
    if not display_name or not ext:
        raise ApiError(400, "invalid_filename", "Nom de fichier invalide ou sans extension.")

    # Lecture bornée : on ne lit jamais plus de max_bytes + 1 octets.
    data = file.stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ApiError(413, "file_too_large", "Fichier trop volumineux.")
    if not data:
        raise ApiError(400, "empty_file", "Fichier vide.")

    mime = detect_mime(data)
    allowed_exts = ALLOWED_TYPES.get(mime)
    if allowed_exts is None:
        raise ApiError(415, "file_type_rejected", "Type de fichier non autorisé.")
    if ext not in allowed_exts:
        raise ApiError(
            415, "extension_mismatch", "L'extension ne correspond pas au contenu réel du fichier."
        )

    return ValidatedUpload(
        data=data,
        display_name=display_name,
        mime_type=mime,
        sha256=hashlib.sha256(data).hexdigest(),
    )


def new_storage_name() -> str:
    return secrets.token_hex(16)


def storage_path(upload_dir: str, storage_name: str) -> str:
    """Construit le chemin disque en revalidant le nom (défense en profondeur).

    Même si la base était altérée (ex. storage_name = "../../app/config.py"),
    on refuse tout ce qui n'est pas exactement 32 caractères hexadécimaux, puis
    on vérifie que le chemin résolu reste dans le répertoire d'upload.
    """
    if not _STORAGE_NAME_RE.fullmatch(storage_name):
        raise ApiError(500, "storage_error", "Erreur de stockage.")
    base = os.path.realpath(upload_dir)
    path = os.path.realpath(os.path.join(base, storage_name))
    if os.path.dirname(path) != base:
        raise ApiError(500, "storage_error", "Erreur de stockage.")
    return path


def write_blob(upload_dir: str, storage_name: str, blob: bytes) -> None:
    """Écriture atomique (fichier temporaire + rename) avec permissions 0600."""
    path = storage_path(upload_dir, storage_name)
    os.makedirs(upload_dir, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=upload_dir, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def read_blob(upload_dir: str, storage_name: str) -> bytes:
    with open(storage_path(upload_dir, storage_name), "rb") as fh:
        return fh.read()


def delete_blob(upload_dir: str, storage_name: str) -> None:
    try:
        os.unlink(storage_path(upload_dir, storage_name))
    except FileNotFoundError:
        pass
# GROGNON
